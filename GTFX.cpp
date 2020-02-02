#pragma warning (disable : 4996)
#pragma comment(lib,"wininet.lib") //remove if not using VC++.
#define _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_WARNINGS
#include "stdafx.h"
#include <iostream>
#include <fstream>
#include "enet/enet.h"
#include <string>
#include <windows.h>
#include <vector>
#include <sstream>
#include <chrono>
#include <fstream>
#include "json.hpp"
#include "bcrypt.h"
#include "crypt_blowfish/crypt_gensalt.c"
#include "crypt_blowfish/crypt_blowfish.h"
#include "crypt_blowfish/crypt_blowfish.c"
#include "crypt_blowfish/wrapper.c"
#include "bcrypt.c"
#include <conio.h>
#include <thread> // TODO
#include <mutex> // TODO
#include <WinSock2.h>
#define _SILENCE_EXPERIMENTAL_FILESYSTEM_DEPRECATION_WARNING
#include <experimental/filesystem>
#include <cstdlib>
#include <cstdio>
#include <algorithm>
#include <cctype>
#include <regex>
#include <filesystem>
#include <wininet.h>
#include <cstring>
#pragma comment(lib,"ws2_32.lib")

using namespace std;
using json = nlohmann::json;

//#define TOTAL_LOG
#define REGISTRATION

ENetHost * server;
int cId = 1;
BYTE* itemsDat = 0;
int itemsDatSize = 0;

/***bcrypt***/

bool verifyPassword(string password, string hash) {
	int ret;
	
	 ret = bcrypt_checkpw(password.c_str(), hash.c_str());
	assert(ret != -1);
	
	return !ret;
}

string hashPassword(string password) {
	char salt[BCRYPT_HASHSIZE];
	char hash[BCRYPT_HASHSIZE];
	int ret;
	
	ret = bcrypt_gensalt(12, salt);
	assert(ret == 0);
	ret = bcrypt_hashpw(password.c_str(), salt, hash);
	assert(ret == 0);
	return hash;
}

/***bcrypt**/

void sendData(ENetPeer* peer, int num, char* data, int len)
{
	/* Create a reliable packet of size 7 containing "packet\0" */
	ENetPacket * packet = enet_packet_create(0,
		len + 5,
		ENET_PACKET_FLAG_RELIABLE);
	/* Extend the packet so and append the string "foo", so it now */
	/* contains "packetfoo\0"                                      */
	/* Send the packet to the peer over channel id 0. */
	/* One could also broadcast the packet by         */
	/* enet_host_broadcast (host, 0, packet);         */
	memcpy(packet->data, &num, 4);
	if (data != NULL)
	{
		memcpy(packet->data+4, data, len);
	}
	char zero = 0;
	memcpy(packet->data + 4 + len, &zero, 1);
	enet_peer_send(peer, 0, packet);
	enet_host_flush(server);
}

int getPacketId(char* data)
{
	return *data;
}

char* getPacketData(char* data)
{
	return data + 4;
}

string text_encode(char* text)
{
	string ret = "";
	while (text[0] != 0)
	{
		switch (text[0])
		{
		case '\n':
			ret += "\\n";
			break;
		case '\t':
			ret += "\\t";
			break;
		case '\b':
			ret += "\\b";
			break;
		case '\\':
			ret += "\\\\";
			break;
		case '\r':
			ret += "\\r";
			break;
		default:
			ret += text[0];
			break;
		}
		text++;
	}
	return ret;
}

int ch2n(char x)
{
	switch (x)
	{
	case '0':
		return 0;
	case '1':
		return 1;
	case '2':
		return 2;
	case '3':
		return 3;
	case '4':
		return 4;
	case '5':
		return 5;
	case '6':
		return 6;
	case '7':
		return 7;
	case '8':
		return 8;
	case '9':
		return 9;
	case 'A':
		return 10;
	case 'B':
		return 11;
	case 'C':
		return 12;
	case 'D':
		return 13;
	case 'E':
		return 14;
	case 'F':
		return 15;
	default:
		break;
	}
}


char* GetTextPointerFromPacket(ENetPacket* packet)
{
	char zero = 0;
	memcpy(packet->data + packet->dataLength - 1, &zero, 1);
	return (char*)(packet->data + 4);
}

BYTE* GetStructPointerFromTankPacket(ENetPacket* packet)
{
	unsigned int packetLenght = packet->dataLength;
	BYTE* result = NULL;
	if (packetLenght >= 0x3C)
	{
		BYTE* packetData = packet->data;
		result = packetData + 4;
		if (*(BYTE*)(packetData + 16) & 8)
		{
			if (packetLenght < *(int*)(packetData + 56) + 60)
			{
				cout << "Packet too small for extended packet to be valid" << endl;
				cout << "Sizeof float is 4.  TankUpdatePacket size: 56" << endl;
				result = 0;
			}
		}
		else
		{
			int zero = 0;
			memcpy(packetData + 56, &zero, 4);
		}
	}
	return result;
}

int GetMessageTypeFromPacket(ENetPacket* packet)
{
	int result;

	if (packet->dataLength > 3u)
	{
		result = *(packet->data);
	}
	else
	{
		cout << "Bad packet length, ignoring message" << endl;
		result = 0;
	}
	return result;
}


vector<string> explode(const string &delimiter, const string &str)
{
	vector<string> arr;

	int strleng = str.length();
	int delleng = delimiter.length();
	if (delleng == 0)
		return arr;//no change

	int i = 0;
	int k = 0;
	while (i<strleng)
	{
		int j = 0;
		while (i + j<strleng && j<delleng && str[i + j] == delimiter[j])
			j++;
		if (j == delleng)//found delimiter
		{
			arr.push_back(str.substr(k, i - k));
			i += delleng;
			k = i;
		}
		else
		{
			i++;
		}
	}
	arr.push_back(str.substr(k, i - k));
	return arr;
}

struct GamePacket
{
	BYTE* data;
	int len;
	int indexes;
};


GamePacket appendFloat(GamePacket p, float val)
{
	//p.data[56] += 1;
	BYTE* n = new BYTE[p.len + 2 + 4];
	memcpy(n, p.data, p.len);
	delete p.data;
	p.data = n;
	n[p.len] = p.indexes;
	n[p.len + 1] = 1;
	memcpy(n + p.len + 2, &val, 4);
	p.len = p.len + 2 + 4;
	p.indexes++;
	return p;
}

GamePacket appendFloat(GamePacket p, float val, float val2)
{
	//p.data[56] += 1;
	BYTE* n = new BYTE[p.len + 2 + 8];
	memcpy(n, p.data, p.len);
	delete p.data;
	p.data = n;
	n[p.len] = p.indexes;
	n[p.len + 1] = 3;
	memcpy(n + p.len + 2, &val, 4);
	memcpy(n + p.len + 6, &val2, 4);
	p.len = p.len + 2 + 8;
	p.indexes++;
	return p;
}

GamePacket appendFloat(GamePacket p, float val, float val2, float val3)
{
	//p.data[56] += 1;
	BYTE* n = new BYTE[p.len + 2 + 12];
	memcpy(n, p.data, p.len);
	delete p.data;
	p.data = n;
	n[p.len] = p.indexes;
	n[p.len + 1] = 4;
	memcpy(n + p.len + 2, &val, 4);
	memcpy(n + p.len + 6, &val2, 4);
	memcpy(n + p.len + 10, &val3, 4);
	p.len = p.len + 2 + 12;
	p.indexes++;
	return p;
}

GamePacket appendInt(GamePacket p, int val)
{
	//p.data[56] += 1;
	BYTE* n = new BYTE[p.len + 2 + 4];
	memcpy(n, p.data, p.len);
	delete p.data;
	p.data = n;
	n[p.len] = p.indexes;
	n[p.len + 1] = 9;
	memcpy(n + p.len + 2, &val, 4);
	p.len = p.len + 2 + 4;
	p.indexes++;
	return p;
}

GamePacket appendIntx(GamePacket p, int val)
{
	//p.data[56] += 1;
	BYTE* n = new BYTE[p.len + 2 + 4];
	memcpy(n, p.data, p.len);
	delete p.data;
	p.data = n;
	n[p.len] = p.indexes;
	n[p.len + 1] = 5;
	memcpy(n + p.len + 2, &val, 4);
	p.len = p.len + 2 + 4;
	p.indexes++;
	return p;
}

GamePacket appendString(GamePacket p, string str)
{
	//p.data[56] += 1;
	BYTE* n = new BYTE[p.len + 2 + str.length() + 4];
	memcpy(n, p.data, p.len);
	delete p.data;
	p.data = n;
	n[p.len] = p.indexes;
	n[p.len + 1] = 2;
	int sLen = str.length();
	memcpy(n+p.len+2, &sLen, 4);
	memcpy(n + p.len + 6, str.c_str(), sLen);
	p.len = p.len + 2 + str.length() + 4;
	p.indexes++;
	return p;
}

GamePacket createPacket()
{
	BYTE* data = new BYTE[61];
	string asdf = "0400000001000000FFFFFFFF00000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
	for (int i = 0; i < asdf.length(); i += 2)
	{
		char x = ch2n(asdf[i]);
		x = x << 4;
		x += ch2n(asdf[i + 1]);
		memcpy(data + (i / 2), &x, 1);
		if (asdf.length() > 61 * 2) throw 0;
	}
	GamePacket packet;
	packet.data = data;
	packet.len = 61;
	packet.indexes = 0;
	return packet;
}

GamePacket packetEnd(GamePacket p)
{
	BYTE* n = new BYTE[p.len + 1];
	memcpy(n, p.data, p.len);
	delete p.data;
	p.data = n;
	char zero = 0;
	memcpy(p.data+p.len, &zero, 1);
	p.len += 1;
	//*(int*)(p.data + 52) = p.len;
	*(int*)(p.data + 56) = p.indexes;//p.len-60;//p.indexes;
	*(BYTE*)(p.data + 60) = p.indexes;
	//*(p.data + 57) = p.indexes;
	return p;
}

struct InventoryItem {
	__int16 itemID;
	__int8 itemCount;
};

struct PlayerInventory {
	vector<InventoryItem> items;
	int inventorySize = 100;
};

#define cloth0 cloth_hair
#define cloth1 cloth_shirt
#define cloth2 cloth_pants
#define cloth3 cloth_feet
#define cloth4 cloth_face
#define cloth5 cloth_hand
#define cloth6 cloth_back
#define cloth7 cloth_mask
#define cloth8 cloth_necklace
#define cloth9 cloth_ances

struct PlayerInfo {
	int effect = 0;
	bool isIn = false;
	int netID;
	bool haveGrowId = false;
	string tankIDName = "";
	string tankIDPass = "";
	string requestedName = "";
	string rawName = "";
	string displayName = "";
	string country = "";
	int adminLevel = 0;
	int userID = 0;
	string currentWorld = "EXIT";
	bool radio = true;
	int x;
	int y;
	int x1;
	int y1;
	int lastPunchX = 0;
	int lastPunchY = 0;
	bool isRotatedLeft = false;

	bool isUpdating = false;
	bool joinClothesUpdated = false;
	int blockbroken = 0; //block broken
	int level = 1;
	int ban = 0;
	int gem = 0;
	bool puncheffect = false;
	bool taped = false;
	bool boughtMEM = false; // vip
	bool boughtFYE = false; // war hammer
	bool boughtAAC = false; // ances
	bool boughtRFS = false; // rayman fist
	bool boughtWSD = false; // winds ring
	bool boughtGRN = false; // gemini
	bool boughtFRC = false; // force ring
	bool boughtDAV = false; // Da vinci wings
	bool boughtFCS = false; // Focused Eyes
	bool boughtDRT = false; // Dr. Tittle
	int cloth_hair = 0; // 0
	int cloth_shirt = 0; // 1
	int cloth_pants = 0; // 2
	int cloth_feet = 0; // 3
	int cloth_face = 0; // 4
	int cloth_hand = 0; // 5
	int cloth_back = 0; // 6
	int cloth_mask = 0; // 7
	int cloth_necklace = 0; // 8
	int cloth_ances = 0;

	int invcount = 0;

	int invitem1 = 0;
	int invitem2 = 0;
	int invitem3 = 0;
	int invitem4 = 0;
	int invitem5 = 0;
	int invitem6 = 0;
	int invitem7 = 0;
	int invitem8 = 0;
	int invitem9 = 0;

	bool canWalkInBlocks = false; // 1
	bool canDoubleJump = false; // 2
	bool isInvisible = false; // 4
	bool isinv = false;
	bool noHands = false; // 8
	bool noEyes = false; // 16
	bool noBody = false; // 32
	bool devilHorns = false; // 64
	bool goldenHalo = false; // 128
	bool isFrozen = false; // 2048
	bool isCursed = false; // 4096
	bool isDuctaped = false; // 8192
	bool haveCigar = false; // 16384
	bool isShining = false; // 32768
	bool isZombie = false; // 65536
	bool isHitByLava = false; // 131072
	bool haveHauntedShadows = false; // 262144
	bool haveGeigerRadiation = false; // 524288
	bool haveReflector = false; // 1048576
	bool isEgged = false; // 2097152
	bool havePineappleFloag = false; // 4194304
	bool haveFlyingPineapple = false; // 8388608
	bool haveSuperSupporterName = false; // 16777216
	bool haveSupperPineapple = false; // 33554432
	bool isGhost = false;
	//bool 
	int skinColor = 0x8295C3FF; //normal SKin color like gt!

	PlayerInventory inventory;

	long long int lastSB = 0;
	long long int lastINV = 0;
	long long int lastBREAK = 0;
};


int getState(PlayerInfo* info) {
	int val = 0;
	val |= info->canWalkInBlocks << 0;
	val |= info->canDoubleJump << 1;
	val |= info->isInvisible << 2;
	val |= info->noHands << 3;
	val |= info->noEyes << 4;
	val |= info->noBody << 5;
	val |= info->devilHorns << 6;
	val |= info->goldenHalo << 7;
	return val;
}


struct WorldItem {
	__int16 foreground = 0;
	__int16 background = 0;
	int breakLevel = 0;
	long long int breakTime = 0;
	bool water = false;
	bool fire = false;
	bool glue = false;
	bool red = false;
	bool green = false;
	bool blue = false;

};

struct WorldInfo {
	int width = 100;
	int height = 60;
	bool nuked = false;
	string name = "TEST";
	WorldItem* items;
	string owner = "";
	int ownerId;
	string worldaccess = "";
	int weather = 0;
	vector<string> accessworld;
	bool isPublic=false;
};

WorldInfo generateWorld(string name, int width, int height)
{
	WorldInfo world;
	world.name = name;
	world.width = width;
	world.height = height;
	world.nuked = false;
	world.items = new WorldItem[world.width*world.height];
	for (int i = 0; i < world.width*world.height; i++)
	{
		if (i >= 3800 && i < 5400 && !(rand() % 50)){ world.items[i].foreground = 10; }
		else if (i >= 3700 && i < 5400) {
			if(i > 5000) {
				if (i % 7 == 0) { world.items[i].foreground = 4;}
				else { world.items[i].foreground = 2; }
			}
			else { world.items[i].foreground = 2; }
		}
		else if (i >= 5400) { world.items[i].foreground = 8; }
		if (i >= 3700)
			world.items[i].background = 14;
		if (i == 3650)
			world.items[i].foreground = 6;
		else if (i >= 3600 && i<3700)
			world.items[i].foreground = 0; //fixed the grass in the world!
		if (i == 3750)
			world.items[i].foreground = 8;
	}
	return world;
}

class PlayerDB {
public:
	static string getProperName(string name);
	static string PlayerDB::fixColors(string text);
	static int playerLogin(ENetPeer* peer, string username, string password);
	static int playerRegister(string username, string password, string passwordverify, string email, string discord);
};

string PlayerDB::getProperName(string name) {
	string newS;
	for (char c : name) newS += (c >= 'A' && c <= 'Z') ? c - ('A' - 'a') : c;
	string ret;
	for (int i = 0; i < newS.length(); i++)
	{
		if (newS[i] == '`') i++; else ret += newS[i];
	}
	string ret2;
	for (char c : ret) if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) ret2 += c;

	string username = ret2;
	if (username == "prn" || username == "con" || username == "aux" || username == "nul" || username == "com1" || username == "com2" || username == "com3" || username == "com4" || username == "com5" || username == "com6" || username == "com7" || username == "com8" || username == "com9" || username == "lpt1" || username == "lpt2" || username == "lpt3" || username == "lpt4" || username == "lpt5" || username == "lpt6" || username == "lpt7" || username == "lpt8" || username == "lpt9") {
		return "";
	}

	return ret2;
}

string PlayerDB::fixColors(string text) {
	string ret = "";
	int colorLevel = 0;
	for (int i = 0; i < text.length(); i++)
	{
		if (text[i] == '`')
		{
			ret += text[i];
			if (i + 1 < text.length())
				ret += text[i + 1];
			
			
			if (i+1 < text.length() && text[i + 1] == '`')
			{
				colorLevel--;
			}
			else {
				colorLevel++;
			}
			i++;
		} else {
			ret += text[i];
		}
	}
	for (int i = 0; i < colorLevel; i++) {
		ret += "``";
	}
	for (int i = 0; i > colorLevel; i--) {
		ret += "`w";
	}
	return ret;
}

int PlayerDB::playerLogin(ENetPeer* peer, string username, string password) {
	std::ifstream ifs("players/" + PlayerDB::getProperName(username) + ".json");
	if (ifs.is_open()) {
		json j;
		ifs >> j;
		string pss = j["password"];
		if (verifyPassword(password, pss)) {
			ENetPeer * currentPeer;

			for (currentPeer = server->peers;
				currentPeer < &server->peers[server->peerCount];
				++currentPeer)
			{
				if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
					continue;
				if (currentPeer == peer)
					continue;
				if (((PlayerInfo*)(currentPeer->data))->rawName == PlayerDB::getProperName(username))
				{
					{
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Someone else logged into this account!"));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(currentPeer, 0, packet);
						delete p.data;
					}
					{
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Someone else was logged into this account! He was kicked out now."));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
					}
					//enet_host_flush(server);
					enet_peer_disconnect_later(currentPeer, 0);
				}
			}
			return 1;
		}
		else {
			return -1;
		}
	}
	else {
		return -2;
	}
}
int PlayerDB::playerRegister(string username, string password, string passwordverify, string email, string discord) {
	username = PlayerDB::getProperName(username);
	if (username.length() < 3) return -2;
	string uname = username;

	if (uname == "CON" || uname == "NUL" || uname == "PRN" || uname == "AUX" || uname == "CLOCK$" || uname == "COM0" || uname == "COM1" || uname == "COM2" || uname == "COM3" || uname == "COM4" || uname == "COM5" || uname == "COM6" || uname == "COM7" || uname == "COM8" || uname == "COM9" || uname == "LPT0" || uname == "LPT1" || uname == "LPT2" || uname == "LPT3" || uname == "LPT4" || uname == "LPT5" || uname == "LPT6" || uname == "LPT7" || uname == "LPT8" || uname == "LPT9")
	{
		return -32;
	}
	if (username.length() < 3) return -2;
	std::ifstream ifs("players/" + username + ".json");
	if (ifs.is_open()) {
		return -1;
	}
	ENetPeer* currentPeer;
	currentPeer = server->peers;
	std::ofstream o("players/" + username + ".json");
	if (!o.is_open()) {
		cout << GetLastError() << endl;
		_getch();
	}
	json j;
	PlayerInfo pinfo;
	j["username"] = username;
	j["password"] = hashPassword(password);
	j["ClothBack"] = 0;
	j["ClothHand"] = 0;
	j["ClothFace"] = 0;
	j["ClothShirt"] = 0;
	j["ClothPants"] = 0;
	j["ClothNeck"] = 0;
	j["ClothHair"] = 0;
	j["ClothFeet"] = 0;
	j["ClothMask"] = 0;
	j["ClothAnces"] = 0;
	j["email"] = email;
	j["banned"] = false;
	j["discord"] = discord;
	j["adminLevel"] = 0;
	j["gem"] = ((PlayerInfo*)(currentPeer->data))->gem;
	j["boughtMEM"] = ((PlayerInfo*)(currentPeer->data))->boughtMEM;
	j["boughtAAC"] = ((PlayerInfo*)(currentPeer->data))->boughtAAC;
	j["boughtFYE"] = ((PlayerInfo*)(currentPeer->data))->boughtFYE;
	j["boughtRFS"] = ((PlayerInfo*)(currentPeer->data))->boughtRFS;
	j["boughtWSD"] = ((PlayerInfo*)(currentPeer->data))->boughtWSD;
	j["boughtGRN"] = ((PlayerInfo*)(currentPeer->data))->boughtGRN;
	j["boughtFRC"] = ((PlayerInfo*)(currentPeer->data))->boughtFRC;
	j["boughtFCS"] = ((PlayerInfo*)(currentPeer->data))->boughtFCS;
	j["boughtDAV"] = ((PlayerInfo*)(currentPeer->data))->boughtDAV;
	j["boughtDRT"] = ((PlayerInfo*)(currentPeer->data))->boughtDRT;
	o << j << std::endl;
	return 1;
}

struct AWorld {
	WorldInfo* ptr;
	WorldInfo info;
	int id;
};

class WorldDB {
public:
	WorldInfo get(string name);
	AWorld get2(string name);
	void flush(WorldInfo info);
	void flush2(AWorld info);
	void save(AWorld info);
	void saveAll();
	void saveRedundant();
	vector<WorldInfo> getRandomWorlds();
	WorldDB();
private:
	vector<WorldInfo> worlds;
};

WorldDB::WorldDB() {
	// Constructor
}

void sendConsoleMsg(ENetPeer* peer, string message) {
	GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), message));
	ENetPacket * packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}

string getStrUpper(string txt) {
	string ret;
	for (char c : txt) ret += toupper(c);
	return ret;
}

AWorld WorldDB::get2(string name) {
	if (worlds.size() > 200) {
#ifdef TOTAL_LOG
		cout << "Saving redundant worlds!" << endl;
#endif
		saveRedundant();
#ifdef TOTAL_LOG
		cout << "Redundant worlds are saved!" << endl;
#endif
	}
	AWorld ret;
	name = getStrUpper(name);
	if (name.length() < 1) throw 1; // too short name
	for (char c : name) {
		if ((c<'A' || c>'Z') && (c<'0' || c>'9'))
			throw 2; // wrong name
	}
	if (name == "EXIT") {
		throw 3;
	}
	if (name == "CON" || name == "PRN" || name == "AUX" || name == "NUL" || name == "COM1" || name == "COM2" || name == "COM3" || name == "COM4" || name == "COM5" || name == "COM6" || name == "COM7" || name == "COM8" || name == "COM9" || name == "LPT1" || name == "LPT2" || name == "LPT3" || name == "LPT4" || name == "LPT5" || name == "LPT6" || name == "LPT7" || name == "LPT8" || name == "LPT9") throw 3;
	for (int i = 0; i < worlds.size(); i++) {
		if (worlds.at(i).name == name)
		{
			ret.id = i;
			ret.info = worlds.at(i);
			ret.ptr = &worlds.at(i);
			return ret;
		}

	}
	std::ifstream ifs("worlds/" + name + ".json");
	if (ifs.is_open()) {

		json j;
		ifs >> j;
		WorldInfo info;
		info.name = j["name"].get<string>();
		info.width = j["width"];
		info.height = j["height"];
		info.nuked = j["nuked"];
		info.owner = j["owner"].get<string>();
		info.isPublic = j["isPublic"];
		json tiles = j["tiles"];
		int square = info.width*info.height;
		info.items = new WorldItem[square];
		for (int i = 0; i < square; i++) {
			info.items[i].foreground = tiles[i]["fg"];
			info.items[i].background = tiles[i]["bg"];
		}
		worlds.push_back(info);
		ret.id = worlds.size() - 1;
		ret.info = info;
		ret.ptr = &worlds.at(worlds.size() - 1);
		return ret;
	}
	else {
		WorldInfo info = generateWorld(name, 100, 60);

		worlds.push_back(info);
		ret.id = worlds.size() - 1;
		ret.info = info;
		ret.ptr = &worlds.at(worlds.size() - 1);
		return ret;
	}
	throw 1;
}

WorldInfo WorldDB::get(string name) {

	return this->get2(name).info;
}

void WorldDB::flush(WorldInfo info)
{
	std::ofstream o("worlds/" + info.name + ".json");
	if (!o.is_open()) {
		cout << GetLastError() << endl;
	}
	json j;
	j["name"] = info.name;
	j["width"] = info.width;
	j["height"] = info.height;
	j["nuked"] = info.nuked;
	j["owner"] = info.owner;
	j["isPublic"] = info.isPublic;
	json tiles = json::array();
	int square = info.width*info.height;
	
	for (int i = 0; i < square; i++)
	{
		json tile;
		tile["fg"] = info.items[i].foreground;
		tile["bg"] = info.items[i].background;
		tiles.push_back(tile);
	}
	j["tiles"] = tiles;
	o << j << std::endl;
}

void WorldDB::flush2(AWorld info)
{
	this->flush(info.info);
}

void WorldDB::save(AWorld info)
{
	flush2(info);
	delete info.info.items;
	worlds.erase(worlds.begin() + info.id);
}

void WorldDB::saveAll()
{
	for (int i = 0; i < worlds.size(); i++) {
		flush(worlds.at(i));
		delete worlds.at(i).items;
	}
	worlds.clear();
}

vector<WorldInfo> WorldDB::getRandomWorlds() {
	vector<WorldInfo> ret;
	for (int i = 0; i < ((worlds.size() < 10) ? worlds.size() : 10); i++)
	{ // load first four worlds, it is excepted that they are special
		ret.push_back(worlds.at(i));
	}
	// and lets get up to 6 random
	if (worlds.size() > 4) {
		for (int j = 0; j < 6; j++)
		{
			bool isPossible = true;
			WorldInfo world = worlds.at(rand() % (worlds.size() - 4));
			for (int i = 0; i < ret.size(); i++)
			{
				if (world.name == ret.at(i).name || world.name == "EXIT")
				{
					isPossible = false;
				}
			}
			if (isPossible)
				ret.push_back(world);
		}
	}
	return ret;
}

void WorldDB::saveRedundant()
{
	for (int i = 4; i < worlds.size(); i++) {
		bool canBeFree = true;
		ENetPeer * currentPeer;

		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (((PlayerInfo*)(currentPeer->data))->currentWorld == worlds.at(i).name)
				canBeFree = false;
		}
		if (canBeFree)
		{
			flush(worlds.at(i));
			delete worlds.at(i).items;
			worlds.erase(worlds.begin() + i);
			i--;
		}
	}
}

//WorldInfo world;
//vector<WorldInfo> worlds;
WorldDB worldDB;

void saveAllWorlds() // atexit hack plz fix
{
	cout << "Saving worlds..." << endl;
	enet_host_destroy(server);
	worldDB.saveAll();
	cout << "Worlds saved!" << endl;
}

WorldInfo* getPlyersWorld(ENetPeer* peer)
{
	try {
		return worldDB.get2(((PlayerInfo*)(peer->data))->currentWorld).ptr;
	} catch(int e) {
		return NULL;
	}
}

struct PlayerMoving {
	int packetType;
	int netID;
	float x;
	float y;
	int characterState;
	int plantingTree;
	float XSpeed;
	float YSpeed;
	int punchX;
	int punchY;

};


enum ClothTypes {
	HAIR,
	SHIRT,
	PANTS,
	FEET,
	FACE,
	HAND,
	BACK,
	MASK,
	NECKLACE,
	ANCES,
	NONE
};

enum BlockTypes {
	FOREGROUND,
	BACKGROUND,
	CONSUMABLE,
	SEED,
	CHECKPOINT,
	WRENCH,
	LOCK,
	GATEWAY,
	PLATFORM,
	SWITCH_BLOCK,
	TRAMPOLINE,
	TOGGLE_FOREGROUND,
	ANIM_FOREGROUND,
	BOUNCY,
	BULLETIN_BOARD,
	CHEST,
	COMPONENT,
	DEADLY,
	FACTION,
	GEMS,
	MAGIC_EGG,
	PORTAL,
	RANDOM_BLOCK,
	SFX_FOREGROUND,
	TREASURE,
	PAIN_BLOCK,
	BEDROCK,
	MAIN_DOOR,
	SIGN,
	DOOR,
	CLOTHING,
	MAILBOX,
	FIST,
	UNKNOWN
};

struct ItemDefinition {
	int id;
	string name;
	int rarity;
	int breakHits;
	int growTime;
	ClothTypes clothType;
	BlockTypes blockType;
	string description = "This item has no description.";
};

vector<ItemDefinition> itemDefs;

struct DroppedItem { // TODO
	int id;
	int uid;
	int count;
};

vector<DroppedItem> droppedItems;

ItemDefinition getItemDef(int id)
{
	if (id < itemDefs.size() && id > -1)
		return itemDefs.at(id);
	/*for (int i = 0; i < itemDefs.size(); i++)
	{
		if (id == itemDefs.at(i).id)
		{
			return itemDefs.at(i);
		}
	}*/
	throw 0;
	return itemDefs.at(0);
}

void craftItemDescriptions() {
	int current = -1;
	std::ifstream infile("Descriptions.txt");
	for (std::string line; getline(infile, line);)
	{
		if (line.length() > 3 && line[0] != '/' && line[1] != '/')
		{
			vector<string> ex = explode("|", line);
			ItemDefinition def;
			if (atoi(ex[0].c_str()) + 1 < itemDefs.size())
			{
				itemDefs.at(atoi(ex[0].c_str())).description = ex[1];
				if (!(atoi(ex[0].c_str()) % 2))
					itemDefs.at(atoi(ex[0].c_str()) + 1).description = "This is a tree.";
			}
		}
	}
}

void LoadPunchEffect(ENetPeer* peer, int clotheffect)
{
	int clothes;
	int effect;
	std::ifstream infile("PunchData.txt");
	for (std::string line; getline(infile, line);)
	{
		if (line.length() > 8 && line[0] != '/' && line[1] != '/')
		{
			vector<string> ex = explode("|", line);
			clothes = atoi(ex[0].c_str());
			effect = atoi(ex[1].c_str());

			if (clotheffect == clothes) {
				((PlayerInfo*)(peer->data))->puncheffect = effect;
			}
		}
	}
}

void buildItemsDatabase()
{
	int current = -1;
	std::ifstream infile("CoreData.txt");
	for (std::string line; getline(infile, line);)
	{
		if (line.length() > 8 && line[0] != '/' && line[1] != '/')
		{
			vector<string> ex = explode("|", line);
			ItemDefinition def;
			def.id = atoi(ex[0].c_str());
			def.name = ex[1];
			def.rarity = atoi(ex[2].c_str());
			string bt = ex[4];
			if (bt == "Foreground_Block") {
				def.blockType = BlockTypes::FOREGROUND;
			}
			else if(bt == "Seed") {
				def.blockType = BlockTypes::SEED;
			}
			else if(bt == "Consummable") {
				def.blockType = BlockTypes::CONSUMABLE;
			}
			else if (bt == "Pain_Block") {
				def.blockType = BlockTypes::PAIN_BLOCK;
			}
			else if (bt == "Main_Door") {
				def.blockType = BlockTypes::MAIN_DOOR;
			}
			else if (bt == "Bedrock") {
				def.blockType = BlockTypes::BEDROCK;
			}
			else if (bt == "Door") {
				def.blockType = BlockTypes::DOOR;
			}
			else if (bt == "Fist") {
				def.blockType = BlockTypes::FIST;
			}
			else if (bt == "Sign") {
				def.blockType = BlockTypes::SIGN;
			}
			else if (bt == "Background_Block") {
				def.blockType = BlockTypes::BACKGROUND;
			}
			else {
				def.blockType = BlockTypes::UNKNOWN;
			}
			def.breakHits = atoi(ex[7].c_str());
			def.growTime = atoi(ex[8].c_str());
			string cl = ex[9];
			if (cl == "None") {
				def.clothType = ClothTypes::NONE;
			}
			else if(cl == "Hat") {
				def.clothType = ClothTypes::HAIR;
			}
			else if(cl == "Shirt") {
				def.clothType = ClothTypes::SHIRT;
			}
			else if(cl == "Pants") {
				def.clothType = ClothTypes::PANTS;
			}
			else if (cl == "Feet") {
				def.clothType = ClothTypes::FEET;
			}
			else if (cl == "Face") {
				def.clothType = ClothTypes::FACE;
			}
			else if (cl == "Hand") {
				def.clothType = ClothTypes::HAND;
			}
			else if (cl == "Back") {
				def.clothType = ClothTypes::BACK;
			}
			else if (cl == "Hair") {
				def.clothType = ClothTypes::MASK;
			}
			else if (cl == "Chest") {
				def.clothType = ClothTypes::NECKLACE;
			}
			else {
				def.clothType = ClothTypes::NONE;
			}
			
			if (++current != def.id)
			{
				cout << "Critical error! Unordered database at item "<< std::to_string(current) <<"/"<< std::to_string(def.id) <<"!" << endl;
			}

			itemDefs.push_back(def);
		}
	}
	craftItemDescriptions();
}

struct Admin {
	string username;
	string password;
	int level = 0;
	long long int lastSB = 0;
};

vector<Admin> admins;

void addAdmin(string username, string password, int level)
{
	Admin admin;
	admin.username = username;
	admin.password = password;
	admin.level = level;
	admins.push_back(admin);
}

int getAdminLevel(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password) {
			return admin.level;
		}
	}
	return 0;
}
bool canSB(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level>1) {
			using namespace std::chrono;
			if (admin.lastSB + 900000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count() || admin.level == 999)
			{
				admins[i].lastSB = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
				return true;
			}
			else {
				return false;
			}
		}
	}
	return false;
}
int adminlevel(string name) {
	bool exist = std::experimental::filesystem::exists("players/" + PlayerDB::getProperName(name) + ".json");

	if (exist)
	{

		std::ifstream ifff("players/" + PlayerDB::getProperName(name) + ".json");
		json j;
		ifff >> j;

		int adminlevel;
		adminlevel = j["adminLevel"];

		ifff.close();

		if (adminlevel == 0 || adminlevel == NULL) {
			return 0;
		}
		else {
			return adminlevel;

		}

	}
	else
	{
		return 0;
	}
}

bool canClear(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password) {
			return admin.level > 0;
		}
	}
	return false;
}

bool isSuperAdmin(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 999) {
			return true;
		}
	}
	return false;
}

bool isCO(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 777) {
			return true;
		}
	}
	return false;
}

bool isMini(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 555) {
			return true;
		}
	}
	return false;
}

bool isVIP(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 333) {
			return true;
		}
	}
	return false;
}

bool isMod(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 666) {
			return true;
		}
	}
	return false;
}

bool isHere(ENetPeer* peer, ENetPeer* peer2)
{
	return ((PlayerInfo*)(peer->data))->currentWorld == ((PlayerInfo*)(peer2->data))->currentWorld;
}

void sendInventory(ENetPeer* peer, PlayerInventory inventory)
{
	string asdf2 = "0400000009A7379237BB2509E8E0EC04F8720B050000000000000000FBBB0000010000007D920100FDFDFDFD04000000040000000000000000000000000000000000";
	int inventoryLen = inventory.items.size();
	int packetLen = (asdf2.length() / 2) + (inventoryLen * 4) + 4;
	BYTE* data2 = new BYTE[packetLen];
	for (int i = 0; i < asdf2.length(); i += 2)
	{
		char x = ch2n(asdf2[i]);
		x = x << 4;
		x += ch2n(asdf2[i + 1]);
		memcpy(data2 + (i / 2), &x, 1);
	}
	int endianInvVal = _byteswap_ulong(inventoryLen);
	memcpy(data2 + (asdf2.length() / 2) - 4, &endianInvVal, 4);
	endianInvVal = _byteswap_ulong(inventory.inventorySize);
	memcpy(data2 + (asdf2.length() / 2) - 8, &endianInvVal, 4);
	int val = 0;
	for (int i = 0; i < inventoryLen; i++)
	{
		val = 0;
		val |= inventory.items.at(i).itemID;
		val |= inventory.items.at(i).itemCount << 16;
		val &= 0x00FFFFFF;
		val |= 0x00 << 24;
		memcpy(data2 + (i*4) + (asdf2.length() / 2), &val, 4);
	}
	ENetPacket * packet3 = enet_packet_create(data2,
		packetLen,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet3);
	delete data2;
	//enet_host_flush(server);
}

BYTE* packPlayerMoving(PlayerMoving* dataStruct)
{
	BYTE* data = new BYTE[56];
	for (int i = 0; i < 56; i++)
	{
		data[i] = 0;
	}
	memcpy(data, &dataStruct->packetType, 4);
	memcpy(data + 4, &dataStruct->netID, 4);
	memcpy(data + 12, &dataStruct->characterState, 4);
	memcpy(data + 20, &dataStruct->plantingTree, 4);
	memcpy(data + 24, &dataStruct->x, 4);
	memcpy(data + 28, &dataStruct->y, 4);
	memcpy(data + 32, &dataStruct->XSpeed, 4);
	memcpy(data + 36, &dataStruct->YSpeed, 4);
	memcpy(data + 44, &dataStruct->punchX, 4);
	memcpy(data + 48, &dataStruct->punchY, 4);
	return data;
}

PlayerMoving* unpackPlayerMoving(BYTE* data)
{
	PlayerMoving* dataStruct = new PlayerMoving;
	memcpy(&dataStruct->packetType, data, 4);
	memcpy(&dataStruct->netID, data + 4, 4);
	memcpy(&dataStruct->characterState, data + 12, 4);
	memcpy(&dataStruct->plantingTree, data + 20, 4);
	memcpy(&dataStruct->x, data + 24, 4);
	memcpy(&dataStruct->y, data + 28, 4);
	memcpy(&dataStruct->XSpeed, data + 32, 4);
	memcpy(&dataStruct->YSpeed, data + 36, 4);
	memcpy(&dataStruct->punchX, data + 44, 4);
	memcpy(&dataStruct->punchY, data + 48, 4);
	return dataStruct;
}

void SendPacket(int a1, string a2, ENetPeer* enetPeer)
{
	if (enetPeer)
	{
		ENetPacket* v3 = enet_packet_create(0, a2.length() + 5, 1);
		memcpy(v3->data, &a1, 4);
		//*(v3->data) = (DWORD)a1;
		memcpy((v3->data) + 4, a2.c_str(), a2.length());

		//cout << std::hex << (int)(char)v3->data[3] << endl;
		enet_peer_send(enetPeer, 0, v3);
	}
}

void SendPacketRaw(int a1, void *packetData, size_t packetDataSize, void *a4, ENetPeer* peer, int packetFlag)
{
	ENetPacket *p;

	if (peer) // check if we have it setup
	{
		if (a1 == 4 && *((BYTE *)packetData + 12) & 8)
		{
			p = enet_packet_create(0, packetDataSize + *((DWORD *)packetData + 13) + 5, packetFlag);
			int four = 4;
			memcpy(p->data, &four, 4);
			memcpy((char *)p->data + 4, packetData, packetDataSize);
			memcpy((char *)p->data + packetDataSize + 4, a4, *((DWORD *)packetData + 13));
			enet_peer_send(peer, 0, p);
		}
		else
		{
			p = enet_packet_create(0, packetDataSize + 5, packetFlag);
			memcpy(p->data, &a1, 4);
			memcpy((char *)p->data + 4, packetData, packetDataSize);
			enet_peer_send(peer, 0, p);
		}
	}
	delete packetData;
}


	void onPeerConnect(ENetPeer* peer)
	{
		ENetPeer * currentPeer;

		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (peer != currentPeer)
			{
				if (isHere(peer, currentPeer))
				{
					string netIdS = std::to_string(((PlayerInfo*)(currentPeer->data))->netID);
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + netIdS + "\nuserID|" + netIdS + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(((PlayerInfo*)(currentPeer->data))->x) + "|" + std::to_string(((PlayerInfo*)(currentPeer->data))->y) + "\nname|``" + ((PlayerInfo*)(currentPeer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(currentPeer->data))->country + "\ninvis|0\nmstate|0\nsmstate|0\n")); // ((PlayerInfo*)(server->peers[i].data))->tankIDName
					ENetPacket * packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);

					enet_peer_send(peer, 0, packet);
					delete p.data;
					string netIdS2 = std::to_string(((PlayerInfo*)(peer->data))->netID);
					GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + netIdS2 + "\nuserID|" + netIdS2 + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(((PlayerInfo*)(peer->data))->x) + "|" + std::to_string(((PlayerInfo*)(peer->data))->y) + "\nname|``" + ((PlayerInfo*)(peer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(peer->data))->country + "\ninvis|0\nmstate|0\nsmstate|0\n")); // ((PlayerInfo*)(server->peers[i].data))->tankIDName
					ENetPacket * packet2 = enet_packet_create(p2.data,
						p2.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(currentPeer, 0, packet2);
					delete p2.data;
					//enet_host_flush(server);
				}
			}
		}
		
	}

	void updateAllClothes(ENetPeer* peer)
	{
		ENetPeer * currentPeer;
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer))
			{
				GamePacket p3 = packetEnd(appendFloat(appendIntx(appendFloat(appendFloat(appendFloat(appendString(createPacket(), "OnSetClothing"), ((PlayerInfo*)(peer->data))->cloth_hair, ((PlayerInfo*)(peer->data))->cloth_shirt, ((PlayerInfo*)(peer->data))->cloth_pants), ((PlayerInfo*)(peer->data))->cloth_feet, ((PlayerInfo*)(peer->data))->cloth_face, ((PlayerInfo*)(peer->data))->cloth_hand), ((PlayerInfo*)(peer->data))->cloth_back, ((PlayerInfo*)(peer->data))->cloth_mask, ((PlayerInfo*)(peer->data))->cloth_necklace), ((PlayerInfo*)(peer->data))->skinColor), 0.0f, 0.0f, 0.0f));
				memcpy(p3.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4); // ffloor
				ENetPacket * packet3 = enet_packet_create(p3.data,
					p3.len,
					ENET_PACKET_FLAG_RELIABLE);

				enet_peer_send(currentPeer, 0, packet3);
				delete p3.data;
				//enet_host_flush(server);
				GamePacket p4 = packetEnd(appendFloat(appendIntx(appendFloat(appendFloat(appendFloat(appendString(createPacket(), "OnSetClothing"), ((PlayerInfo*)(currentPeer->data))->cloth_hair, ((PlayerInfo*)(currentPeer->data))->cloth_shirt, ((PlayerInfo*)(currentPeer->data))->cloth_pants), ((PlayerInfo*)(currentPeer->data))->cloth_feet, ((PlayerInfo*)(currentPeer->data))->cloth_face, ((PlayerInfo*)(currentPeer->data))->cloth_hand), ((PlayerInfo*)(currentPeer->data))->cloth_back, ((PlayerInfo*)(currentPeer->data))->cloth_mask, ((PlayerInfo*)(currentPeer->data))->cloth_necklace), ((PlayerInfo*)(currentPeer->data))->skinColor), 0.0f, 0.0f, 0.0f));
				memcpy(p4.data + 8, &(((PlayerInfo*)(currentPeer->data))->netID), 4); // ffloor
				ENetPacket * packet4 = enet_packet_create(p4.data,
					p4.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(peer, 0, packet4);
				delete p4.data;
				//enet_host_flush(server);
			}
		}
	}

	void sendClothes(ENetPeer* peer)
	{
		ENetPeer * currentPeer;
		GamePacket p3 = packetEnd(appendFloat(appendIntx(appendFloat(appendFloat(appendFloat(appendString(createPacket(), "OnSetClothing"), ((PlayerInfo*)(peer->data))->cloth_hair, ((PlayerInfo*)(peer->data))->cloth_shirt, ((PlayerInfo*)(peer->data))->cloth_pants), ((PlayerInfo*)(peer->data))->cloth_feet, ((PlayerInfo*)(peer->data))->cloth_face, ((PlayerInfo*)(peer->data))->cloth_hand), ((PlayerInfo*)(peer->data))->cloth_back, ((PlayerInfo*)(peer->data))->cloth_mask, ((PlayerInfo*)(peer->data))->cloth_necklace), ((PlayerInfo*)(peer->data))->skinColor), ((PlayerInfo*)(peer->data))->cloth_ances, 0.0f, 0.0f));
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer))
			{
				
				memcpy(p3.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4); // ffloor
				ENetPacket * packet3 = enet_packet_create(p3.data,
					p3.len,
					ENET_PACKET_FLAG_RELIABLE);

				enet_peer_send(currentPeer, 0, packet3);
			}

		}
		//enet_host_flush(server);
		delete p3.data;
	}

	void sendPData(ENetPeer* peer, PlayerMoving* data)
	{
		ENetPeer * currentPeer;

		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (peer != currentPeer)
			{
				if (isHere(peer, currentPeer))
				{
					data->netID = ((PlayerInfo*)(peer->data))->netID;

					SendPacketRaw(4, packPlayerMoving(data), 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
				}
			}
		}
	}

	void updateInvis(ENetPeer* peer)
	{
		ENetPeer* currentPeer;
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer))
			{

				GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnInvis"), ((PlayerInfo*)(peer->data))->isinv));

				memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
				ENetPacket* packet2 = enet_packet_create(p2.data,
					p2.len,
					ENET_PACKET_FLAG_RELIABLE);

				enet_peer_send(currentPeer, 0, packet2);
				delete p2.data;

				GamePacket p3 = packetEnd(appendInt(appendString(createPacket(), "OnInvis"), ((PlayerInfo*)(currentPeer->data))->isinv));

				memcpy(p3.data + 8, &(((PlayerInfo*)(currentPeer->data))->netID), 4);
				ENetPacket* packet3 = enet_packet_create(p3.data,
					p3.len,
					ENET_PACKET_FLAG_RELIABLE);

				enet_peer_send(peer, 0, packet3);
				delete p3.data;
				if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 0) {
					if (((PlayerInfo*)(peer->data))->boughtDRT == true) {
						((PlayerInfo*)(peer->data))->displayName = "`4Dr. " + ((PlayerInfo*)(peer->data))->tankIDName;
					}
				}
				if (((PlayerInfo*)(peer->data))->level >= 125) {
					GamePacket p2ww = packetEnd(appendString(appendString(createPacket(), "OnCountryState"), ((PlayerInfo*)(peer->data))->country + "|showGuild|maxLevel"));
					memcpy(p2ww.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
					ENetPacket* packet2ww = enet_packet_create(p2ww.data,
						p2ww.len,
						ENET_PACKET_FLAG_RELIABLE);

					enet_peer_send(currentPeer, 0, packet2ww);
					delete p2ww.data;
					GamePacket p2wwee = packetEnd(appendString(appendString(createPacket(), "OnCountryState"), ((PlayerInfo*)(currentPeer->data))->country + "|showGuild|maxLevel"));
					memcpy(p2wwee.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
					ENetPacket* packet2wwee = enet_packet_create(p2wwee.data,
						p2wwee.len,
						ENET_PACKET_FLAG_RELIABLE);

					enet_peer_send(peer, 0, packet2wwee);
					delete p2wwee.data;
				}
				else {
					GamePacket p2ww = packetEnd(appendString(appendString(createPacket(), "OnCountryState"), ((PlayerInfo*)(peer->data))->country + "|showGuild"));
					memcpy(p2ww.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
					ENetPacket* packet2ww = enet_packet_create(p2ww.data,
						p2ww.len,
						ENET_PACKET_FLAG_RELIABLE);

					enet_peer_send(currentPeer, 0, packet2ww);
					delete p2ww.data;
					GamePacket p2wwee = packetEnd(appendString(appendString(createPacket(), "OnCountryState"), ((PlayerInfo*)(currentPeer->data))->country + "|showGuild"));
					memcpy(p2wwee.data + 8, &(((PlayerInfo*)(currentPeer->data))->netID), 4);
					ENetPacket* packet2wwee = enet_packet_create(p2wwee.data,
						p2wwee.len,
						ENET_PACKET_FLAG_RELIABLE);

					enet_peer_send(peer, 0, packet2wwee);
					delete p2wwee.data;
				}

			}

		}
	}

	int getPlayersCountInWorld(string name)
	{
		int count = 0;
		ENetPeer * currentPeer;
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (((PlayerInfo*)(currentPeer->data))->currentWorld == name)
				count++;
		}
		return count;
	}
	void showWrong(ENetPeer* peer, string listFull, string itemFind) {
		GamePacket fff = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`wFind item: " + itemFind + "``|left|206|\nadd_spacer|small|\n" + listFull + "add_textbox|Enter a word below to find the item|\nadd_text_input|item|Item Name||30|\nend_dialog|findid|Cancel|Find the item!|\n"));
		ENetPacket* packetd = enet_packet_create(fff.data,
			fff.len,
			ENET_PACKET_FLAG_RELIABLE);
		enet_peer_send(peer, 0, packetd);

		//enet_host_flush(server);
		delete fff.data;
	}
	void sendRoulete(ENetPeer* peer, int x, int y)
	{
		ENetPeer* currentPeer;
		int val = rand() % 37;
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer))
			{
				GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`w[" + ((PlayerInfo*)(peer->data))->displayName + " `wspun the wheel and got `6"+std::to_string(val)+"`w!]"), 0));
				ENetPacket * packet2 = enet_packet_create(p2.data,
					p2.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(currentPeer, 0, packet2);
				delete p2.data;
			}
				

			//cout << "Tile update at: " << data2->punchX << "x" << data2->punchY << endl;
		}
	}
	void sendWorld(ENetPeer* peer, WorldInfo* worldInfo)
	{
#ifdef TOTAL_LOG
		cout << "Entering a world..." << endl;
#endif
		((PlayerInfo*)(peer->data))->joinClothesUpdated = false;
		string asdf = "0400000004A7379237BB2509E8E0EC04F8720B050000000000000000FBBB0000010000007D920100FDFDFDFD04000000040000000000000000000000070000000000"; // 0400000004A7379237BB2509E8E0EC04F8720B050000000000000000FBBB0000010000007D920100FDFDFDFD04000000040000000000000000000000080000000000000000000000000000000000000000000000000000000000000048133A0500000000BEBB0000070000000000
		string worldName = worldInfo->name;
		int xSize = worldInfo->width;
		int ySize = worldInfo->height;
		int square = xSize * ySize;
		__int16 nameLen = worldName.length();
		int payloadLen = asdf.length() / 2;
		int dataLen = payloadLen + 2 + nameLen + 12 + (square * 8) + 4;
		int allocMem = payloadLen + 2 + nameLen + 12 + (square * 8) + 4 + 16000;
		BYTE* data = new BYTE[allocMem];
		for (int i = 0; i < asdf.length(); i += 2)
		{
			char x = ch2n(asdf[i]);
			x = x << 4;
			x += ch2n(asdf[i + 1]);
			memcpy(data + (i / 2), &x, 1);
		}
		int zero = 0;
		__int16 item = 0;
		int smth = 0;
		for (int i = 0; i < square * 8; i += 4) memcpy(data + payloadLen + i + 14 + nameLen, &zero, 4);
		for (int i = 0; i < square * 8; i += 8) memcpy(data + payloadLen + i + 14 + nameLen, &item, 2);
		memcpy(data + payloadLen, &nameLen, 2);
		memcpy(data + payloadLen + 2, worldName.c_str(), nameLen);
		memcpy(data + payloadLen + 2 + nameLen, &xSize, 4);
		memcpy(data + payloadLen + 6 + nameLen, &ySize, 4);
		memcpy(data + payloadLen + 10 + nameLen, &square, 4);
		BYTE* blockPtr = data + payloadLen + 14 + nameLen;
		for (int i = 0; i < square; i++) {
			if ((worldInfo->items[i].foreground == 0) || (worldInfo->items[i].foreground == 2) || (worldInfo->items[i].foreground == 8) || (worldInfo->items[i].foreground == 100)/* || (worldInfo->items[i].foreground%2)*/)
			{
				memcpy(blockPtr, &worldInfo->items[i].foreground, 2);
				int type = 0x00000000;
				// type 1 = locked
				if (worldInfo->items[i].water)
					type |= 0x04000000;
				if (worldInfo->items[i].glue)
					type |= 0x08000000;
				if (worldInfo->items[i].fire)
					type |= 0x10000000;
				if (worldInfo->items[i].red)
					type |= 0x20000000;
				if (worldInfo->items[i].green)
					type |= 0x40000000;
				if (worldInfo->items[i].blue)
					type |= 0x80000000;

				// int type = 0x04000000; = water
				// int type = 0x08000000 = glue
				// int type = 0x10000000; = fire
				// int type = 0x20000000; = red color
				// int type = 0x40000000; = green color
				// int type = 0x80000000; = blue color
				memcpy(blockPtr + 4, &type, 4);
				/*if (worldInfo->items[i].foreground % 2)
				{
					blockPtr += 6;
				}*/
			}
			else
			{
				memcpy(blockPtr, &zero, 2);
			}
			memcpy(blockPtr + 2, &worldInfo->items[i].background, 2);
			blockPtr += 8;
			/*if (blockPtr - data < allocMem - 2000) // realloc
			{
				int wLen = blockPtr - data;
				BYTE* oldData = data;

				data = new BYTE[allocMem + 16000];
				memcpy(data, oldData, allocMem);
				allocMem += 16000;
				delete oldData;
				blockPtr = data + wLen;

			}*/
		}
		memcpy(data + dataLen - 4, &smth, 4);
		ENetPacket* packet2 = enet_packet_create(data,
			dataLen,
			ENET_PACKET_FLAG_RELIABLE);
		enet_peer_send(peer, 0, packet2);
		//enet_host_flush(server);
		for (int i = 0; i < square; i++) {
			if ((worldInfo->items[i].foreground == 0) || (worldInfo->items[i].foreground == 2) || (worldInfo->items[i].foreground == 8) || (worldInfo->items[i].foreground == 100))
				; // nothing
			else
			{
				PlayerMoving data;
				//data.packetType = 0x14;
				data.packetType = 0x3;

				//data.characterState = 0x924; // animation
				data.characterState = 0x0; // animation
				data.x = i % worldInfo->width;
				data.y = i / worldInfo->height;
				data.punchX = i % worldInfo->width;
				data.punchY = i / worldInfo->width;
				data.XSpeed = 0;
				data.YSpeed = 0;
				data.netID = -1;
				data.plantingTree = worldInfo->items[i].foreground;
				SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
			}
		}
		((PlayerInfo*)(peer->data))->currentWorld = worldInfo->name;
		delete data;

	}
	void joinWorld(ENetPeer* peer, string act, int x2, int y2)
	{
		try {
			WorldInfo info = worldDB.get(act);
			sendWorld(peer, &info);


			int x = 3040;
			int y = 736;

			for (int j = 0; j < info.width * info.height; j++)
			{
				if (info.items[j].foreground == 6) {
					x = (j % info.width) * 32;
					y = (j / info.width) * 32;
				}
			}


			if (x2 != 0 && y2 != 0)
			{
				x = x2;
				y = y2;
			}
			int id = 244;
			GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + std::to_string(cId) + "\nuserID|" + std::to_string(cId) + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(x) + "|" + std::to_string(y) + "\nname|``" + ((PlayerInfo*)(peer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(peer->data))->country + "|" + std::to_string(id) + "\ninvis|0\nmstate|0\nsmstate|0\ntype|local\n"));
			//GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + std::to_string(cId) + "\nuserID|" + std::to_string(cId) + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(x) + "|" + std::to_string(y) + "\nname|``" + ((PlayerInfo*)(peer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(peer->data))->country + "\ninvis|0\nmstate|0\nsmstate|0\ntype|local\n"));
			ENetPacket* packet = enet_packet_create(p.data,
				p.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet);
			delete p.data;

			/* Weather change
			{
				GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), info.weather));
				ENetPacket * packet = enet_packet_create(p.data,
					p.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(peer, 0, packet);
				delete p.data;
			}
			*/

			((PlayerInfo*)(peer->data))->netID = cId;
			onPeerConnect(peer);
			cId++;
			sendInventory(peer, ((PlayerInfo*)(peer->data))->inventory);



			WorldInfo* world = getPlyersWorld(peer);
			string nameworld = world->name;
			string ownerworld = world->owner;
			int count = 0;
			ENetPeer* currentPeer;
			string name = "";
			for (currentPeer = server->peers;
				currentPeer < &server->peers[server->peerCount];
				++currentPeer)
			{
				if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
					continue;
				count++;
			}


			{
				ENetPeer* currentPeer;

				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (isHere(peer, currentPeer))
					{


						/*GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
						ENetPacket * packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet2);
						delete p2.data;

						int effect = ((PlayerInfo*)(peer->data))->entereffect;*/
						int x = ((PlayerInfo*)(peer->data))->x;
						int y = ((PlayerInfo*)(peer->data))->y;
						/*GamePacket psp = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), effect), x, y));

						ENetPacket * packetd = enet_packet_create(psp.data,
							psp.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(currentPeer, 0, packetd);
						delete psp.data;*/
					}

				}

			}
			//updateInvis(peer);
			//sendPuncheffect(peer, ((PlayerInfo*)(peer->data))->puncheffect);
			/*{
				ENetPeer* currentPeer;

				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (isHere(peer, currentPeer))
					{

						int ID = ((PlayerInfo*)(currentPeer->data))->puncheffect;
						((PlayerInfo*)(currentPeer->data))->puncheffect = ID;
						sendPuncheffect(currentPeer);

					}

				}

			}
			*/





			int otherpeople = 0;

			for (currentPeer = server->peers;
				currentPeer < &server->peers[server->peerCount];
				++currentPeer)
			{
				if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
					continue;
				if (isHere(peer, currentPeer))
					otherpeople++;
			}
			int otherpeoples = otherpeople - 1;

			GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oWorld `0" + nameworld + " `oentered. There are `0" + std::to_string(otherpeoples) + " `oother people here`7, `0" + std::to_string(count) + " `oonline."));
			ENetPacket* packet2 = enet_packet_create(p2.data,
				p2.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet2);
			delete p2.data;
			if (ownerworld != "") {
				GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`5[`0" + nameworld + " `$World Locked `oby " + ownerworld + "`5]"));
				ENetPacket* packet3 = enet_packet_create(p3.data,
					p3.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(peer, 0, packet3);
				delete p3.data;
			}

			/*if (((PlayerInfo*)(peer->data))->mute == 1) {
				((PlayerInfo*)(peer->data))->cantsay = true;
				sendState(peer);
			}*/
			GamePacket p22 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`5<`w" + ((PlayerInfo*)(peer->data))->displayName + "`` `5entered, `w" + std::to_string(otherpeoples) + "`` others here>``"));


			for (currentPeer = server->peers;
				currentPeer < &server->peers[server->peerCount];
				++currentPeer)
			{
				if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
					continue;
				/*if (isHere(peer, currentPeer) && ((PlayerInfo*)(peer->data))->isMod == 0) {
					{

						ENetPacket * packet2 = enet_packet_create(p22.data,
							p22.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(currentPeer, 0, packet2);

					}
				}*/
			}


		}
		catch (int e) {
			if (e == 1) {
				((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
				GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You have exited the world."));
				ENetPacket* packet = enet_packet_create(p.data,
					p.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(peer, 0, packet);
				delete p.data;
				//enet_host_flush(server);
			}
			else if (e == 2) {
				((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
				GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You have entered bad characters in the world name!"));
				ENetPacket* packet = enet_packet_create(p.data,
					p.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(peer, 0, packet);
				delete p.data;
				//enet_host_flush(server);
			}
			else if (e == 3) {
				((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
				GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Exit from what? Click back if you're done playing."));
				ENetPacket* packet = enet_packet_create(p.data,
					p.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(peer, 0, packet);
				delete p.data;
				//enet_host_flush(server);
			}
			else {
				((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
				GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "I know this menu is magical and all, but it has its limitations! You can't visit this world!"));
				ENetPacket* packet = enet_packet_create(p.data,
					p.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(peer, 0, packet);
				delete p.data;
				//enet_host_flush(server);
			}
		}
	}
	void sendPlayerLeave(ENetPeer* peer, PlayerInfo* player)
	{
		ENetPeer* currentPeer;
		int count = 0;
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			count++;
		}
		sendConsoleMsg(peer, "Where would you like to go? (`w" + std::to_string(count) + " `oonline)");
		GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnRemove"), "netID|" + std::to_string(player->netID) + "\n")); // ((PlayerInfo*)(server->peers[i].data))->tankIDName
		GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`5<`w" + player->displayName + "`5 left, `w" + std::to_string(getPlayersCountInWorld(player->currentWorld) - 1) + "`5 others here>``"));
		GamePacket p3 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`5<`w" + player->displayName + "`5 left, `w" + std::to_string(getPlayersCountInWorld(player->currentWorld) - 1) + "`5 others here>``"), 0));
		string text = "action|play_sfx\nfile|audio/door_shut.wav\ndelayMS|0\n";
		BYTE* data = new BYTE[5 + text.length()];
		BYTE zero = 0;
		int type = 3;
		memcpy(data, &type, 4);
		memcpy(data + 4, text.c_str(), text.length());
		memcpy(data + 4 + text.length(), &zero, 1);

		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer)) {
				{
					ENetPacket* packet1 = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);

					enet_peer_send(currentPeer, 0, packet1);

					if (!((PlayerInfo*)(peer->data))->isGhost) {
						ENetPacket* packet3 = enet_packet_create(p3.data,
							p3.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet3);
					}

					if (((PlayerInfo*)(peer->data))->currentWorld != "EXIT") {
						ENetPacket* packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet2);
						if (!((PlayerInfo*)(peer->data))->isGhost) {

							ENetPacket* packet4 = enet_packet_create(data,
								5 + text.length(),
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(currentPeer, 0, packet4);

						}
					}
				}
			}
		}
		delete p.data;
		delete p2.data;
		delete p3.data;
		delete data;
	}
	void sendNothingHappened(ENetPeer* peer, int x, int y) {
		PlayerMoving data;
		data.netID = ((PlayerInfo*)(peer->data))->netID;
		data.packetType = 0x8;
		data.plantingTree = 0;
		data.netID = -1;
		data.x = x;
		data.y = y;
		data.punchX = x;
		data.punchY = y;
		SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
	}
	void sendDrop(ENetPeer* peer, int netID, int x, int y, int item, int count, BYTE specialEffect)
	{
		if (item >= 7196) return;
		if (item < 0) return;
		ENetPeer* currentPeer;
		string name = "";
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer)) {
				PlayerMoving data;
				data.packetType = 14;
				data.x = x;
				data.y = y;
				data.netID = netID;
				data.plantingTree = item;
				float val = count; // item count
				BYTE val2 = specialEffect;

				BYTE* raw = packPlayerMoving(&data);
				memcpy(raw + 16, &val, 4);
				memcpy(raw + 1, &val2, 1);

				SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
			}
		}
	}
	void sendtake(ENetPeer* peer, int netID, int x, int y, int item)
	{
		if (item >= 7196) return;
		if (item < 0) return;
		ENetPeer* currentPeer;
		string name = "";
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer)) {
				PlayerMoving data;
				data.packetType = 14;
				data.x = x;
				data.y = y;
				data.netID = netID;
				data.plantingTree = item;


				BYTE* raw = packPlayerMoving(&data);


				SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_EVENT_TYPE_RECEIVE);
			}
		}
	}
	void sendTileUpdate(int x, int y, int tile, int causedBy, ENetPeer* peer)
	{
		PlayerMoving data;
		//data.packetType = 0x14;
		data.packetType = 0x3;

		//data.characterState = 0x924; // animation
		data.characterState = 0x0; // animation
		data.x = x;
		data.y = y;
		data.punchX = x;
		data.punchY = y;
		data.XSpeed = 0;
		data.YSpeed = 0;
		data.netID = causedBy;
		data.plantingTree = tile;

		WorldInfo* world = getPlyersWorld(peer);

		if (world == NULL) return;
		if (x<0 || y<0 || x>world->width || y>world->height) return;
		sendNothingHappened(peer, x, y);
		if (world->items[x + (y * world->width)].foreground == 758)
			sendRoulete(peer, x, y);


		if (((PlayerInfo*)(peer->data))->haveGrowId == false) {
			if (tile == 242) {

				GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`4You must register before you can lock a world!``"), 0));


				ENetPacket* packet2 = enet_packet_create(p2.data,
					p2.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(peer, 0, packet2);
				delete p2.data;

				return;

			}

		}
		if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass))
		{
			if (world->items[x + (y * world->width)].foreground == 6 || world->items[x + (y * world->width)].foreground == 8 || world->items[x + (y * world->width)].foreground == 3760) {
				GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`wIt's too strong to break.``"), 0));


				ENetPacket* packet2 = enet_packet_create(p2.data,
					p2.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(peer, 0, packet2);
				delete p2.data;

				return;
			}

			if (tile == 6 || tile == 8 || tile == 3760 || tile == 1790 || tile == 1900 || tile == 7372)
			{
				GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`wIt's too strong to break.``"), 0));


				ENetPacket* packet2 = enet_packet_create(p2.data,
					p2.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(peer, 0, packet2);
				delete p2.data;

				return;
			}
		}
		if (world->name == "ADMIN" && !getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass))
		{
			if (world->items[x + (y * world->width)].foreground == 758)
				sendRoulete(peer, x, y);
			return;
		}
		if (world->items[x + (y * world->width)].foreground == 1790)
		{
			if (tile == 32) {
				string ownername = world->owner;

				GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`9The Legendary Wizard!`|left|1790|\nadd_label|small|`oGreetings, traveler! I am the Legendary Wizard. Should you wish to embark on a Legendary Quest, simply choose one below.``|left|4|\n\nadd_spacer|small|\nadd_button|legendname|`9Quest For Honor``|0|0|\nadd_button|legenddragon|`9Quest For Fire``|0|0|\nadd_button|legendbot|`9Quest Of Steel``|0|0|\nadd_button|legendwing|`9Quest Of The Heavens``|0|0|\nadd_button|legendkatana|`9Quest For The Blade``|0|0|\nadd_button|legendwhip|`9Quest For Candour``|0|0|\nadd_spacer|small|\nadd_quick_exit|\nend_dialog|noty|No Thanks||gazette||"));
				ENetPacket* packet = enet_packet_create(p.data,
					p.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(peer, 0, packet);

				//enet_host_flush(server);
				delete p.data;

				return;
			}
		}
		if (world->items[x + (y * world->width)].foreground == 2)
		{
			if (tile == 32) {
				string ownername = world->owner;

				GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|`wEdit Vending Machine|left|2078|\nadd_spacer|small|\nadd_label_with_icon|small|`wThis vending machine Contains: `2NONE|left|2946|\nadd_spacer|small|\nadd_button|emptyvend|`wEmpty the Machine|\nadd_spacer|small|\nadd_button|netid|Add Something|\nadd_spacer|small|\nend_dialog|chc0|Cancel|\n"));
				ENetPacket* packet = enet_packet_create(p.data,
					p.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(peer, 0, packet);

				//enet_host_flush(server);
				delete p.data;

				return;
			}
		}
		if (world->items[x + (y * world->width)].foreground == 1900) {


			if (tile == 32) {
				string ownername = world->owner;

				GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`9The Ringmaster!`|left|1900|\nadd_label|small|`oGreetings, traveler! I am the Ringmaster. Should you wish to embark on a Ring, simply choose one below.``|left|4|\n\nadd_spacer|small|\nadd_button|ringforce|`9Ring Of Force``|0|0|\nadd_button|ringwinds|`9Ring Of Winds``|0|0|\nadd_button|ringone|`9The One Ring``|0|0|\nadd_button|ringwisdom|`9Ring of Wisdom ``|0|0|\nadd_button|ringwater|`9Ring Of Water``|0|0|\nadd_button|ringsaving|`9Ring Of Savings``|0|0|\nadd_button|ringsmithing|`9Ring Of Smithing``|0|0|\nadd_button|ringshrinking|`9Ring Of Shrinking``|0|0|\nadd_button|ringnature|`9Ring of Nature``|0|0|\nadd_button|geminiring|`9Gemini Ring``|0|0|\nadd_spacer|small|\nadd_quick_exit|\nend_dialog|noty|No Thanks||gazette||"));
				ENetPacket* packet = enet_packet_create(p.data,
					p.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(peer, 0, packet);

				//enet_host_flush(server);
				delete p.data;

				return;
			}
		}
		if (world->name != "ADMIN") {
			if (world->owner != "") {

				if (((PlayerInfo*)(peer->data))->rawName == world->owner || (((PlayerInfo*)(peer->data))->rawName == world->worldaccess || isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass))) {
					if (((PlayerInfo*)(peer->data))->rawName == "") return;
					if (world->items[x + (y * world->width)].foreground == 2398) {
						if (world->items[x + (y * world->width)].foreground == 242 && (((PlayerInfo*)(peer->data))->rawName == world->worldaccess))
						{
							return;
						}

						if (tile == 32 && ((PlayerInfo*)(peer->data))->rawName == world->worldaccess) {
							return;
						}

						if (tile == 32) {


							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`9Locke The Salesman`|left|2398|\nadd_label|small|`oGreetings, traveler! I am Locke The Salesman. What should i do for you? Simply choose one below.``|left|4|\n\nadd_spacer|small|\nadd_button|weather|`2Change Weather``|0|0|\nadd_button|searchitems|`2Search item``|0|0|\nadd_spacer|small|\nadd_quick_exit|\nend_dialog|noty|No Thanks||gazette||"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);

							//enet_host_flush(server);
							delete p.data;

							return;
						}
					}
				}
			}
		}
		if (world->name != "ADMIN") {
			if (world->owner != "") {

				if (((PlayerInfo*)(peer->data))->rawName == world->owner || (((PlayerInfo*)(peer->data))->rawName == world->worldaccess || isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) || isMod(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass))) {
					if (((PlayerInfo*)(peer->data))->rawName == "") return;
					// WE ARE GOOD TO GO

					if (world->items[x + (y * world->width)].foreground == 242 && (((PlayerInfo*)(peer->data))->rawName == world->worldaccess))
					{
						return;
					}

					if (tile == 32 && ((PlayerInfo*)(peer->data))->rawName == world->worldaccess) {
						return;
					}
					string offlinelist = "";
					string offname = "";
					int ischecked;

					for (std::vector<string>::const_iterator i = world->accessworld.begin(); i != world->accessworld.end(); ++i) {
						offname = *i;
						offlinelist += "\nadd_checkbox|isAccessed|" + offname + "|0|\n";

					}

					if (world->isPublic == true) {
						ischecked = 1;
					}
					else {
						ischecked = 0;
					}
					if (tile == 32) {
						if (world->accessworld.size() == 0) {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wEdit World Lock``|left|242|\nadd_textbox|`wAccess list:|left|\nadd_spacer|small|\nadd_textbox|Currently, you're the only one with the access.|left|\nadd_spacer|small|\nadd_player_picker|netid|`wAdd|\nadd_checkbox|isWorldPublic|Allow anyone to build|" + std::to_string(ischecked) + "| \nend_dialog|wlmenu|Cancel|OK|"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}

						else {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wEdit World Lock``|left|242|\nadd_textbox|`wAccess list:|left|\nadd_spacer|small|" + offlinelist + "add_spacer|small|\nadd_player_picker|netid|`wAdd|\nadd_checkbox|isWorldPublic|Allow anyone to build|" + std::to_string(ischecked) + "| \nend_dialog|wlmenu|Cancel|OK|"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}

					}

				}
				if (world->name != "ADMIN") {
					if (world->owner != "") {
						if (((PlayerInfo*)(peer->data))->userID == world->ownerId || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) > 2) {
							// WE ARE GOOD TO GO
							if (tile == 32) {
								if (world->items[x + (y * world->width)].foreground == 3832) { // stuff weather dialog
									if (x != 0)
									{
										((PlayerInfo*)(peer->data))->lastPunchX = x;
									}
									if (y != 0)
									{
										((PlayerInfo*)(peer->data))->lastPunchY = y;
									}
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wEdit Weather Machine``|left|3832|\nadd_spacer|small|\nadd_textbox|`wPlease add an item that you'd like to apply to this weather machine!|\nadd_spacer|small|\nadd_item_picker|stuffitem|`wEdit Item|Select Weather - Item|\nadd_spacer|small|\nadd_text_input|gravity|Gravity Value: ||4|\nadd_spacer|small|\nadd_quick_exit|\nend_dialog|stuff|Nevermind||"));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete p.data;
								}
								if (getItemDef(world->items[x + (y * world->width)].foreground).blockType == BlockTypes::LOCK)
								{
									((PlayerInfo*)(peer->data))->lastPunchX = x;
									((PlayerInfo*)(peer->data))->lastPunchY = y;
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\nadd_label_with_icon|big|`wEdit World Lock``|left|242|\nadd_label|small|`wAccess list:``|left\nadd_spacer|small|\nadd_label|small|Currently, you're the only one with access.``|left\nadd_spacer|small|\nadd_player_picker|playerNetID|`wAdd``|\nadd_checkbox|checkbox_public|Allow anyone to Build and Break|0\nadd_checkbox|checkbox_disable_music|Disable Custom Music Blocks|0\nadd_text_input|tempo|Music BPM|100|3|\nadd_checkbox|checkbox_disable_music_render|Make Custom Music Blocks invisible|noflags|0|0|\nend_dialog|lock_edit|Cancel|OK|")); //\nadd_button|getKey|Get World Key|noflags|0|0|
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete p.data;
								}
							}
						}




						else if (world->isPublic)
						{
							if (world->items[x + (y * world->width)].foreground == 242)
							{
								string ownername = world->owner;

								GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`0" + ownername + "'s `$World Lock`0. (Open to Public)"), 0));


								ENetPacket* packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet2);
								delete p2.data;

								return;
							}

						}
						else {
							return;
						} /*lockeds*/
						if (tile == 242) {



							GamePacket p3 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`0Only one `$World Lock`0 can be placed in a world!"), 0));


							ENetPacket* packet3 = enet_packet_create(p3.data,
								p3.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet3);
							delete p3.data;
							return;
						}

					}
				}



				if (tile == 1404) {
					//world->items[x + (y*world->width)].water = !world->items[x + (y*world->width)].water;
					//if (isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) {

					if (((PlayerInfo*)(peer->data))->rawName == world->owner || isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) {
						if (world->items[x + (y * world->width)].foreground != 0) {
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "There is no space for the Main Door!"));


							ENetPacket* packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet2);
							delete p2.data;

						}
						else if (world->items[x + (y * world->width) + 100].foreground != 0) {
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "There is no space for the Main Door!"));


							ENetPacket* packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet2);
							delete p2.data;

						}
						else

						{
							//	showDoormover(peer);
							for (int i = 0; i < world->width * world->height; i++)
							{
								if (i >= 5400) {
									world->items[i].foreground = 8;
								}
								else if (world->items[i].foreground == 6) {

									world->items[i].foreground = 0;
									world->items[i + 100].foreground = 0;

								}

								else if (world->items[i].foreground != 6) {
									world->items[x + (y * world->width)].foreground = 6;
									world->items[x + (y * world->width) + 100].foreground = 8;
								}


							}

							WorldInfo* wrld = getPlyersWorld(peer);
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									string act = ((PlayerInfo*)(peer->data))->currentWorld;
									//WorldInfo info = worldDB.get(act);
									// sendWorld(currentPeer, &info);


									sendPlayerLeave(currentPeer, (PlayerInfo*)(currentPeer->data));
									joinWorld(currentPeer, act, 0, 0);
									updateAllClothes(peer);
									GamePacket p8 = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "You moved the Main-Door!"));
									ENetPacket* packet8 = enet_packet_create(p8.data,
										p8.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet8);

								}

							}
						}
						return;
					}
				}
				if (tile == 32) {
					// TODO
					return;
				}
				if (tile == 822) {
					world->items[x + (y * world->width)].water = !world->items[x + (y * world->width)].water;
					return;
				}
				if (tile == 3062)
				{
					world->items[x + (y * world->width)].fire = !world->items[x + (y * world->width)].fire;
					return;
				}
				if (tile == 1866)
				{
					world->items[x + (y * world->width)].glue = !world->items[x + (y * world->width)].glue;
					return;
				}
				ItemDefinition def;
				try {
					def = getItemDef(tile);
					if (def.clothType != ClothTypes::NONE) return;
				}
				catch (int e) {
					def.breakHits = 4;
					def.blockType = BlockTypes::UNKNOWN;
#ifdef TOTAL_LOG
					cout << "Ugh, unsupported item " << tile << endl;
#endif
				}

				if (tile == 544 || tile == 546 || tile == 4520 || tile == 382 || tile == 3116 || tile == 4520 || tile == 1792 || tile == 5666 || tile == 2994 || tile == 4368) return;
				if (tile == 5708 || tile == 5709 || tile == 5780 || tile == 5781 || tile == 5782 || tile == 5783 || tile == 5784 || tile == 5785 || tile == 5710 || tile == 5711 || tile == 5786 || tile == 5787 || tile == 5788 || tile == 5789 || tile == 5790 || tile == 5791 || tile == 6146 || tile == 6147 || tile == 6148 || tile == 6149 || tile == 6150 || tile == 6151 || tile == 6152 || tile == 6153 || tile == 5670 || tile == 5671 || tile == 5798 || tile == 5799 || tile == 5800 || tile == 5801 || tile == 5802 || tile == 5803 || tile == 5668 || tile == 5669 || tile == 5792 || tile == 5793 || tile == 5794 || tile == 5795 || tile == 5796 || tile == 5797 || tile == 544 || tile == 546 || tile == 4520 || tile == 382 || tile == 3116 || tile == 1792 || tile == 5666 || tile == 2994 || tile == 4368) return;
				if (tile == 1902 || tile == 1508 || tile == 428) return;
				if (tile == 410 || tile == 1770 || tile == 4720 || tile == 4882 || tile == 6392 || tile == 3212 || tile == 1832 || tile == 4742 || tile == 3496 || tile == 3270 || tile == 4722) return;
				if (tile >= 7558) return;
				if (tile == 0 || tile == 18) {

					if (world->items[x + (y * world->width)].background == 6864 && world->items[x + (y * world->width)].foreground == 0) return;
					if (world->items[x + (y * world->width)].background == 0 && world->items[x + (y * world->width)].foreground == 0) return;
					//data.netID = -1;
					data.packetType = 0x8;
					data.plantingTree = 4; // old is 4
					using namespace std::chrono;
					//if (world->items[x + (y*world->width)].foreground == 0) return;
					if ((duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count() - world->items[x + (y * world->width)].breakTime >= 4000)
					{
						world->items[x + (y * world->width)].breakTime = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
						world->items[x + (y * world->width)].breakLevel = 4; // TODO

					}
					else
						if (y < world->height && world->items[x + (y * world->width)].breakLevel + 4 >= def.breakHits * 4) { // TODO
							data.packetType = 0x3;// 0xC; // 0xF // World::HandlePacketTileChangeRequest
							data.netID = -1;
							data.plantingTree = tile;
							data.punchX = x;
							data.punchY = y;
							world->items[x + (y * world->width)].breakLevel = 0;
							if (world->items[x + (y * world->width)].foreground != 0)

							{
								if (world->items[x + (y * world->width)].foreground == 242)
								{
									world->owner = "";
									world->worldaccess = "";
									world->isPublic = true;

									world->accessworld = {};

									WorldInfo* world = getPlyersWorld(peer);
									string nameworld = world->name;
									GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`5[`w" + nameworld + " `ohas had its `$World Lock `oremoved!`5]"));
									ENetPacket* packet3 = enet_packet_create(p3.data,
										p3.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet3);
								}
								if (world->items[x + (y * world->width)].foreground == 3402)
								{


									int x = 3040;
									int y = 736;



									std::vector<int> list{ 384, 386, 388,1458, 390, 4422, 4424, 4416, 5644, 5652, 366, 364, 362 ,2390, 2396, 2384 };
									int index = rand() % list.size(); // pick a random index
									int value = list[index];

									if (value == 390) {
										sendDrop(peer, -1, x, y, value, 5, 0);
									}
									else {

										sendDrop(peer, -1, data.punchX, data.punchY, value, 1, 0);
									}
								}
								world->items[x + (y * world->width)].foreground = 0;

								//world->items[x + (y*world->width)].background = 0;
								{ // gem thing

									int valzz = rand() % 10;
									((PlayerInfo*)(peer->data))->gem = ((PlayerInfo*)(peer->data))->gem + valzz;


									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(peer, 0, packet);
									delete p.data;
									// levelup code starts here
									((PlayerInfo*)(peer->data))->blockbroken = ((PlayerInfo*)(peer->data))->blockbroken + 1;
									int level = ((PlayerInfo*)(peer->data))->level;
									if (((PlayerInfo*)(peer->data))->blockbroken == 150) //block need to break to level up!
									{

										int blc = ((PlayerInfo*)(peer->data))->blockbroken;
										((PlayerInfo*)(peer->data))->blockbroken = 0; // set to 0
										((PlayerInfo*)(peer->data))->level = ((PlayerInfo*)(peer->data))->level + 1; // level up


										ENetPeer* currentPeer;

										for (currentPeer = server->peers;
											currentPeer < &server->peers[server->peerCount];
											++currentPeer)
										{
											if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
												continue;
											if (isHere(peer, currentPeer)) {
												string name = ((PlayerInfo*)(peer->data))->displayName;

												GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`2" + name + " `wis now level " + std::to_string(((PlayerInfo*)(peer->data))->level) + "!"));
												string text = "action|play_sfx\nfile|audio/levelup2.wav\ndelayMS|0\n";
												BYTE* data = new BYTE[5 + text.length()];
												BYTE zero = 0;
												int type = 3;
												memcpy(data, &type, 4);
												memcpy(data + 4, text.c_str(), text.length());
												memcpy(data + 4 + text.length(), &zero, 1);
												ENetPacket* packet = enet_packet_create(p.data,
													p.len,
													ENET_PACKET_FLAG_RELIABLE);
												enet_peer_send(currentPeer, 0, packet);

												ENetPacket* packet2 = enet_packet_create(data,
													5 + text.length(),
													ENET_PACKET_FLAG_RELIABLE);

												enet_peer_send(currentPeer, 0, packet2);
												int effect = 46;
												int x = ((PlayerInfo*)(peer->data))->x;
												int y = ((PlayerInfo*)(peer->data))->y;
												GamePacket psp = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), effect), x, y));

												ENetPacket* packetd = enet_packet_create(psp.data,
													psp.len,
													ENET_PACKET_FLAG_RELIABLE);
												enet_peer_send(currentPeer, 0, packetd);

												//                `w(`2" + std::to_string(level) + "`w) "
												//((PlayerInfo*)(peer->data))->displayName = "`w(`2"+((PlayerInfo*)(peer->data))->level +"`w) " + ((PlayerInfo*)(peer->data))->tankIDName;
												GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnNameChanged"), "`w(`2" + std::to_string(((PlayerInfo*)(peer->data))->level) + "`w) " + ((PlayerInfo*)(peer->data))->displayName));


												memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
												ENetPacket* packet2ss = enet_packet_create(p2.data,
													p2.len,
													ENET_PACKET_FLAG_RELIABLE);

												enet_peer_send(currentPeer, 0, packet2ss);
												delete p2.data;
												delete psp.data;
												delete data;
												delete p.data;

												GamePacket p3 = packetEnd(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`2" + name + " `wis now level " + std::to_string(((PlayerInfo*)(peer->data))->level) + "!"));
												ENetPacket* packet3 = enet_packet_create(p3.data,
													p3.len,
													ENET_PACKET_FLAG_RELIABLE);
												enet_peer_send(currentPeer, 0, packet3);

												/*if (((PlayerInfo*)(peer->data))->haveGrowId) {

													PlayerInfo* p = ((PlayerInfo*)(peer->data));

													string username = PlayerDB::getProperName(p->rawName);



													 std::ofstream o("players/" + username + ".json");
													if (!o.is_open()) {
														cout << GetLastError() << endl;
														_getch();
													}
													json j;

													int clothback = p->cloth_back;
													int clothhand = p->cloth_hand;
													int clothface = p->cloth_face;
													int clothhair = p->cloth_hair;
													int clothfeet = p->cloth_feet;
													int clothpants = p->cloth_pants;
													int clothneck = p->cloth_necklace;
													int clothshirt = p->cloth_shirt;
													int clothmask = p->cloth_mask;
													int level = p->level;

													int gem = p->gem;
													int ban = p->ban;
													// int puncheffect = p->puncheffect;

													string password = ((PlayerInfo*)(peer->data))->tankIDPass;
													j["username"] = username;
													j["password"] = hashPassword(password);
													j["adminLevel"] = p->adminLevel;
													j["ClothBack"] = clothback;
													j["ClothHand"] = clothhand;
													j["ClothFace"] = clothface;
													j["ClothShirt"] = clothshirt;
													j["ClothPants"] = clothpants;
													j["ClothNeck"] = clothneck;
													j["ClothHair"] = clothhair;
													j["ClothFeet"] = clothfeet;
													j["ClothMask"] = clothmask;
													j["Level"] = level; //save the level

													j["isBanned"] = ban;
													//  j["puncheffect"] = puncheffect;
													o << j << std::endl;
												}*/




												delete p3.data;

											}
										}
									}
								}
							}



							else {
								world->items[x + (y * world->width)].background = 0;
								data.plantingTree = 6864;
								world->items[x + (y * world->width)].background = 6864;

								/*GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`1Test``"));
								ENetPacket * packetd = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packetd);
								delete p2.data;
								return;*/
							}

						}
						else
							if (y < world->height)
							{
								world->items[x + (y * world->width)].breakTime = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
								world->items[x + (y * world->width)].breakLevel += 4; // TODO
								if (world->items[x + (y * world->width)].foreground == 758)
									sendRoulete(peer, x, y);
							}

				}
				else {
					for (int i = 0; i < ((PlayerInfo*)(peer->data))->inventory.items.size(); i++)
					{
						if (((PlayerInfo*)(peer->data))->inventory.items.at(i).itemID == tile)
						{
							if ((unsigned int)((PlayerInfo*)(peer->data))->inventory.items.at(i).itemCount > 1)
							{
								((PlayerInfo*)(peer->data))->inventory.items.at(i).itemCount--;
							}
							else {
								((PlayerInfo*)(peer->data))->inventory.items.erase(((PlayerInfo*)(peer->data))->inventory.items.begin() + i);

							}
						}
					}
					if (def.blockType == BlockTypes::BACKGROUND)
					{
						world->items[x + (y * world->width)].background = tile;
					}
					else {
						world->items[x + (y * world->width)].foreground = tile;
						if (tile == 242) {
							world->owner = ((PlayerInfo*)(peer->data))->rawName;

							world->isPublic = false;
							ENetPeer* currentPeer;



							string nameworld = world->name;
							string ownerworld = world->owner;
							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer)) {
									{
										GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`5[`w" + nameworld + "`o has been `$World Locked `oby " + ownerworld + "`5]"));

										ENetPacket* packetd = enet_packet_create(p2.data,
											p2.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(currentPeer, 0, packetd);
										GamePacket p23 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`5[`w" + nameworld + "`w has been `$World Locked `wby " + ownerworld + "`5]"), 0));

										ENetPacket* packet23 = enet_packet_create(p23.data,
											p23.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(currentPeer, 0, packet23);
										delete p23.data;
										delete p2.data;

									}
								}
							}
						}
					}

					world->items[x + (y * world->width)].breakLevel = 0;

				}

				ENetPeer* currentPeer;

				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (isHere(peer, currentPeer))
						SendPacketRaw(4, packPlayerMoving(&data), 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);

					//cout << "Tile update at: " << data2->punchX << "x" << data2->punchY << endl;
				}
			}
		}
	}

	void sendPlayerEnter(ENetPeer* peer, PlayerInfo* player)
	{
		sendInventory(peer, ((PlayerInfo*)(peer->data))->inventory);
		ENetPeer* currentPeer;
		int count = 0;
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			count++;
		}
		if (((PlayerInfo*)(peer->data))->haveGrowId)
		{
		}
		WorldInfo* world = getPlyersWorld(peer);
		string nameworld = world->name;
		GamePacket penter1 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`5<`w" + player->displayName + "`5 entered, `w" + std::to_string(getPlayersCountInWorld(player->currentWorld)) + "`5 others here>``"), 0));
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer))
			{
				if (!((PlayerInfo*)(peer->data))->isGhost)
				{
					ENetPacket* packet3 = enet_packet_create(penter1.data,
						penter1.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(currentPeer, 0, packet3);
				}
			}
		}
		GamePacket penter2 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`5<`w" + ((PlayerInfo*)(peer->data))->displayName + "`` `5entered, `w" + std::to_string(getPlayersCountInWorld(player->currentWorld) - 1) + "`` others here>``"));
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer))
			{
				if (!((PlayerInfo*)(peer->data))->isGhost)
				{
					ENetPacket* packet3 = enet_packet_create(penter2.data,
						penter2.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(currentPeer, 0, packet3);
				}
			}
		}
		GamePacket p5 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oWorld `w" + nameworld + " `oentered. There are `w" + std::to_string(getPlayersCountInWorld(player->currentWorld) - 1) + " `oother people here, `w" + std::to_string(count) + " `oonline."));
		ENetPacket* packet5 = enet_packet_create(p5.data,
			p5.len,
			ENET_PACKET_FLAG_RELIABLE);
		enet_peer_send(peer, 0, packet5);
		GamePacket p3 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`5<`w" + player->displayName + "`5 entered, `w" + std::to_string(getPlayersCountInWorld(player->currentWorld)) + "`5 others here>``"), 0));
		string text = "action|play_sfx\nfile|audio/door_open.wav\ndelayMS|0\n";
		BYTE* data = new BYTE[5 + text.length()];
		BYTE zero = 0;
		int type = 3;
		memcpy(data, &type, 4);
		memcpy(data + 4, text.c_str(), text.length());
		memcpy(data + 4 + text.length(), &zero, 1);
		ENetPacket* packet2 = enet_packet_create(data,
			5 + text.length(),
			ENET_PACKET_FLAG_RELIABLE);

		enet_peer_send(currentPeer, 0, packet2);
		enet_peer_send(peer, 0, packet2);
		delete data;
		delete p5.data;
		if (isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass))
		{
			GamePacket penter1 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`5<`w" + ((PlayerInfo*)(peer->data))->displayName + "`` `5entered, `w" + std::to_string(getPlayersCountInWorld(player->currentWorld) - 1) + "`` others here>``"));
			string text = "action|play_sfx\nfile|audio/door_open.wav\ndelayMS|0\n";
			BYTE* data = new BYTE[5 + text.length()];
			BYTE zero = 0;
			int type = 3;
			memcpy(data, &type, 4);
			memcpy(data + 4, text.c_str(), text.length());
			memcpy(data + 4 + text.length(), &zero, 1);
			delete data;
			for (currentPeer = server->peers;
				currentPeer < &server->peers[server->peerCount];
				++currentPeer)
			{
				if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
					continue;
				if (isHere(peer, currentPeer))
				{
					if (!((PlayerInfo*)(peer->data))->isGhost)
					{
						ENetPacket* packet3 = enet_packet_create(penter1.data,
							penter1.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(currentPeer, 0, packet3);
					}
				}
			}
		}
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer))
			{


				GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
				ENetPacket* packet2 = enet_packet_create(p2.data,
					p2.len,
					ENET_PACKET_FLAG_RELIABLE);

				enet_peer_send(currentPeer, 0, packet2);
				delete p2.data;
				continue;
				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (isHere(peer, currentPeer)) {
						if (!((PlayerInfo*)(peer->data))->isGhost) {
							ENetPacket* packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(currentPeer, 0, packet2);

							ENetPacket* packet4 = enet_packet_create(data,
								5 + text.length(),
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(currentPeer, 0, packet4);
							if (!((PlayerInfo*)(peer->data))->isGhost) {
								ENetPacket* packet = enet_packet_create(p3.data,
									p3.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packet);
							}
						}
					}
				}
				delete p2.data;
			}
		}
	}
	



	void sendChatMessage(ENetPeer* peer, int netID, string message)
	{

		if (!((PlayerInfo*)(peer->data))->haveGrowId) {
			GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Register first in able to talk."));
			ENetPacket* packet = enet_packet_create(p.data,
				p.len,
				ENET_PACKET_FLAG_RELIABLE);

			enet_peer_send(peer, 0, packet);
			delete p.data;
		}
		else {

			if (isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) > 0)
			{
				ENetPeer* currentPeer;
				string name = "";
				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (((PlayerInfo*)(currentPeer->data))->netID == netID)
						name = ((PlayerInfo*)(currentPeer->data))->displayName;

				}
				GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`o<`w" + name + "`o>`5 " + message));
				GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), netID), "`5" + message), 0));
				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (isHere(peer, currentPeer))
					{

						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet);

						//enet_host_flush(server);

						ENetPacket* packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(currentPeer, 0, packet2);

						//enet_host_flush(server);
					}
				}
				delete p.data;
				delete p2.data;
			}
			else if (isMod(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) > 0)
			{
				ENetPeer* currentPeer;
				string name = "";
				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (((PlayerInfo*)(currentPeer->data))->netID == netID)
						name = ((PlayerInfo*)(currentPeer->data))->displayName;

				}
				GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`o<`w" + name + "`o>`^ " + message));
				GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), netID), "`^" + message), 0));
				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (isHere(peer, currentPeer))
					{

						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet);

						//enet_host_flush(server);

						ENetPacket* packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(currentPeer, 0, packet2);

						//enet_host_flush(server);
					}
				}
				delete p.data;
				delete p2.data;
			}
			else if (isVIP(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) > 0)
			{
				ENetPeer* currentPeer;
				string name = "";
				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (((PlayerInfo*)(currentPeer->data))->netID == netID)
						name = ((PlayerInfo*)(currentPeer->data))->displayName;

				}
				GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`o<`w" + name + "`o>`1 " + message));
				GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), netID), "`1" + message), 0));
				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (isHere(peer, currentPeer))
					{

						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet);

						//enet_host_flush(server);

						ENetPacket* packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(currentPeer, 0, packet2);

						//enet_host_flush(server);
					}
				}
				delete p.data;
				delete p2.data;
			}
			else
			{
				if (message.length() != 0) {
					ENetPeer* currentPeer;
					string name = "";
					for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
					{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
							continue;
						if (((PlayerInfo*)(currentPeer->data))->netID == netID)
							name = ((PlayerInfo*)(currentPeer->data))->displayName;

					}

					for (char c : message)
						if (c < 0x18)
						{
							return;
						}

					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`o<`w" + name + "`o>`w " + message));
					GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), netID), "`w" + message), 0));
					for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
					{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
							continue;
						if (isHere(peer, currentPeer))
						{

							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(currentPeer, 0, packet);

							//enet_host_flush(server);

							ENetPacket* packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(currentPeer, 0, packet2);

							//enet_host_flush(server);
						}
					}
					delete p.data;
					delete p2.data;
				}
			}
		}
	}
	void sendWho(ENetPeer* peer)
	{
		ENetPeer * currentPeer;
		string name = "";
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer))
			{
				if(((PlayerInfo*)(currentPeer->data))->isGhost)
					continue;
				GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(currentPeer->data))->netID), ((PlayerInfo*)(currentPeer->data))->displayName), 1));
				ENetPacket * packet2 = enet_packet_create(p2.data,
					p2.len,
					ENET_PACKET_FLAG_RELIABLE);

				enet_peer_send(peer, 0, packet2);
				delete p2.data;
				//enet_host_flush(server);
			}
		}
	}

	void sendAction(ENetPeer* peer, int netID, string action)
	{
		ENetPeer * currentPeer;
		string name = "";
		GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnAction"), action));
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer)) {
				
				memcpy(p2.data + 8, &netID, 4);
				ENetPacket * packet2 = enet_packet_create(p2.data,
					p2.len,
					ENET_PACKET_FLAG_RELIABLE);

				enet_peer_send(currentPeer, 0, packet2);
				
				//enet_host_flush(server);
			}
		}
		delete p2.data;
	}

	void sendState(ENetPeer* peer) {
		//return; // TODO
		PlayerInfo* info = ((PlayerInfo*)(peer->data));
		int netID = info->netID;
		ENetPeer * currentPeer;
		int state = getState(info);
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer)) {
				PlayerMoving data;
				data.packetType = 0x14;
				data.characterState = 0; // animation
				data.x = 1000;
				data.y = 100;
				data.punchX = 0;
				data.punchY = 0;
				data.XSpeed = 300;
				data.YSpeed = 600;
				data.netID = netID;
				data.plantingTree = state;
				BYTE* raw = packPlayerMoving(&data);
				int var = 0x808000; // placing and breking
				memcpy(raw+1, &var, 3);
				SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
			}
		}
		// TODO
	}

	void sendPlayerToPlayer(ENetPeer* peer, ENetPeer* otherpeer)
	{
		{
			sendPlayerLeave(peer, (PlayerInfo*)(peer->data));
		}
		WorldInfo info = worldDB.get(((PlayerInfo*)(otherpeer->data))->currentWorld);
		sendWorld(peer, &info);

		int x = ((PlayerInfo*)(otherpeer->data))->x;
		int y = ((PlayerInfo*)(otherpeer->data))->y;

		GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + std::to_string(cId) + "\nuserID|" + std::to_string(cId) + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(x) + "|" + std::to_string(y) + "\nname|``" + ((PlayerInfo*)(peer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(peer->data))->country + "\ninvis|0\nmstate|0\nsmstate|0\ntype|local\n"));

		ENetPacket * packet = enet_packet_create(p.data,
			p.len,
			ENET_PACKET_FLAG_RELIABLE);
		enet_peer_send(peer, 0, packet);

		delete p.data;
		((PlayerInfo*)(peer->data))->netID = cId;
		onPeerConnect(peer);
		cId++;

		sendInventory(peer, ((PlayerInfo*)(peer->data))->inventory);
	}

	void sendWorldOffers(ENetPeer* peer)
	{
		if (!((PlayerInfo*)(peer->data))->isIn) return;
		vector<WorldInfo> worlds = worldDB.getRandomWorlds();
		string worldOffers = "default|";
		if (worlds.size() > 0) {
			worldOffers += worlds[0].name;
		}
		
		worldOffers += "\nadd_button|`2PVP`w/`wFFA|PVP|1|9591241481\n";
		for (int i = 0; i < worlds.size(); i++) {
			worldOffers += "add_floater|"+worlds[i].name+"|"+std::to_string(getPlayersCountInWorld(worlds[i].name))+"|0.55|3529161471\n";
		}
		//GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnRequestWorldSelectMenu"), "default|GO FOR IT\nadd_button|Showing: `wFake Worlds``|_catselect_|0.6|3529161471|\nadd_floater|Subscribe|5|0.55|3529161471\nadd_floater|Growtopia|4|0.52|4278190335\nadd_floater|Noobs|150|0.49|3529161471\nadd_floater|...|3|0.49|3529161471\nadd_floater|`6:O :O :O``|2|0.46|3529161471\nadd_floater|SEEMS TO WORK|2|0.46|3529161471\nadd_floater|?????|1|0.43|3529161471\nadd_floater|KEKEKEKEK|13|0.7|3417414143\n"));
		//for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";
		GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnRequestWorldSelectMenu"), worldOffers));
		ENetPacket * packet3 = enet_packet_create(p3.data,
			p3.len,
			ENET_PACKET_FLAG_RELIABLE);
		enet_peer_send(peer, 0, packet3);
		delete p3.data;
		//enet_host_flush(server);
	}





	BOOL WINAPI HandlerRoutine(DWORD dwCtrlType)
	{
		saveAllWorlds();
		return FALSE;
	}

	std::ifstream::pos_type filesize(const char* filename)
	{
		std::ifstream in(filename, std::ifstream::ate | std::ifstream::binary);
		return in.tellg();
	}

	uint32_t HashString(unsigned char* str, int len)
	{
		if (!str) return 0;

		unsigned char* n = (unsigned char*)str;
		uint32_t acc = 0x55555555;

		if (len == 0)
		{
			while (*n)
				acc = (acc >> 27) + (acc << 5) + *n++;
		}
		else
		{
			for (int i = 0; i < len; i++)
			{
				acc = (acc >> 27) + (acc << 5) + *n++;
			}
		}
		return acc;

	}

	unsigned char* getA(string fileName, int* pSizeOut, bool bAddBasePath, bool bAutoDecompress)
	{
		unsigned char* pData = NULL;
		FILE* fp = fopen(fileName.c_str(), "rb");
		if (!fp)
		{
			cout << "File not found" << endl;
			if (!fp) return NULL;
		}

		fseek(fp, 0, SEEK_END);
		*pSizeOut = ftell(fp);
		fseek(fp, 0, SEEK_SET);

		pData = (unsigned char*)new unsigned char[((*pSizeOut) + 1)];
		if (!pData)
		{
			printf("Out of memory opening %s?", fileName.c_str());
			return 0;
		}
		pData[*pSizeOut] = 0;
		fread(pData, *pSizeOut, 1, fp);
		fclose(fp);

		return pData;
	}

	/*
	action|log
msg|`4UPDATE REQUIRED!`` : The `$V2.981`` update is now available for your device.  Go get it!  You'll need to install it before you can play online.
[DBG] Some text is here: action|set_url
url|http://ubistatic-a.akamaihd.net/0098/20180909/GrowtopiaInstaller.exe
label|Download Latest Version
	*/
int _tmain(int argc, _TCHAR* argv[])
{
	cout << "Growtopia private server (c) Growtopia Noobs" << endl;
	cout << "Server Created by Luc1Fer#1337 And Valkrie#1234" << endl;
	enet_initialize();
	if (atexit(saveAllWorlds)) {
		cout << "Saving current Worlds.." << endl;
		cout << "Worlds are Saved!" << endl;
	}
	/*if (RegisterApplicationRestart(L" -restarted", 0) == S_OK)
	{
		cout << "Autorestart is ready" << endl;
	}
	else {
		cout << "Binding autorestart failed!" << endl;
	}
	Sleep(65000);
	int* p = NULL;
	*p = 5;*/
	SetConsoleCtrlHandler(HandlerRoutine, true);
	addAdmin("luc1fer", "Kk123Aa1", 999);
	addAdmin("luc1fer", "Kk123Aa1", 666);
	addAdmin("luc1fer", "Kk123Aa1", 333);
	addAdmin("valkrie", "pro", 999);
	addAdmin("valkrie", "pro", 666);
	addAdmin("valkrie", "pro", 333);
	addAdmin("demon", "123123123", 555);
	addAdmin("rainbow", "lovebts", 999);
	int itemdathash;
	// load items.dat
	{
		std::ifstream file("items.dat", std::ios::binary | std::ios::ate);
		itemsDatSize = file.tellg();



		itemsDat = new BYTE[60 + itemsDatSize];
		string asdf = "0400000010000000FFFFFFFF000000000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
		for (int i = 0; i < asdf.length(); i += 2)
		{
			char x = ch2n(asdf[i]);
			x = x << 4;
			x += ch2n(asdf[i + 1]);
			memcpy(itemsDat + (i / 2), &x, 1);
			if (asdf.length() > 60 * 2) throw 0;
		}
		memcpy(itemsDat + 56, &itemsDatSize, 4);
		file.seekg(0, std::ios::beg);


		if (file.read((char*)(itemsDat + 60), itemsDatSize))
		{
			uint8_t* pData;
			int size = 0;
			const char filename[] = "items.dat";
			size = filesize(filename);
			pData = getA((string)filename, &size, false, false);
			cout << "Updating items data success! Hash: " << HashString((unsigned char*)pData, size) << endl;
			itemdathash = HashString((unsigned char*)pData, size);
			file.close();
		}
		else {
			cout << "Updating item data failed!" << endl;
		}
	}
	

	//world = generateWorld();
	ENetAddress address;
	/* Bind the server to the default localhost.     */
	/* A specific host address can be specified by   */
	enet_address_set_host (&address, "0.0.0.0");
	//address.host = ENET_HOST_ANY;
	/* Bind the server to port 1234. */
	address.port = 17092;
	server = enet_host_create(&address /* the address to bind the server host to */,
		1024      /* allow up to 32 clients and/or outgoing connections */,
		10      /* allow up to 2 channels to be used, 0 and 1 */,
		0      /* assume any amount of incoming bandwidth */,
		0      /* assume any amount of outgoing bandwidth */);
	if (server == NULL)
	{
		fprintf(stderr,
			"An error occured while Trying to UP the Server, This could possibly happen due to the 'items.dat' File is Missing.\n");
		while (1);
		exit(EXIT_FAILURE);
	}
	server->checksum = enet_crc32;
	enet_host_compress_with_range_coder(server);

	buildItemsDatabase();

	ENetEvent event;
	/* Wait up to 1000 milliseconds for an event. */
	while (true)
	while (enet_host_service(server, &event, 1000) > 0)
	{
		ENetPeer* peer = event.peer;
		switch (event.type)
		{
		case ENET_EVENT_TYPE_CONNECT:
		{
#ifdef TOTAL_LOG
			printf("A new client connected.\n");
#endif
			/* Store any relevant client information here. */
			//event.peer->data = "Client information";
			ENetPeer * currentPeer;
			int count = 0;
			for (currentPeer = server->peers;
				currentPeer < &server->peers[server->peerCount];
				++currentPeer)
			{
				if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
					continue;
				if (currentPeer->address.host == peer->address.host)
					count++;
			}

			event.peer->data = new PlayerInfo;
			if (count > 3)
			{
				GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`rToo many accounts are logged on from this IP. Log off one account before playing please.``"));
				ENetPacket * packet = enet_packet_create(p.data,
					p.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(peer, 0, packet);
				delete p.data;
				//enet_host_flush(server);
				enet_peer_disconnect_later(peer, 0);
			}
			else {
				sendData(peer, 1, 0, 0);
			}


			continue;
		}
		case ENET_EVENT_TYPE_RECEIVE:
		{
			if (((PlayerInfo*)(peer->data))->isUpdating)
			{
				cout << "packet drop" << endl;
				continue;
			}
			/*printf("A packet of length %u containing %s was received from %s on channel %u.\n",
				event.packet->dataLength,
				event.packet->data,
				event.peer->data,
				event.channelID);
			cout << (int)*event.packet->data << endl;*/
			//cout << text_encode(getPacketData((char*)event.packet->data));
			/*for (int i = 0; i < event.packet->dataLength; i++)
			{
				cout << event.packet->data[i];
			}
			sendData(7, 0, 0);
			string x = "eventType|0\neventName|102_PLAYER.AUTHENTICATION\nAuthenticated|0\nAuthentication_error|6\nDevice_Id|^^\nGrow_Id|0\nName|^^Elektronik\nWordlock_balance|0\n";
			//string x = "eventType | 0\neventName | 102_PLAYER.AUTHENTICATION\nAuthenticated | 0\nAuthentication_error | 6\nDevice_Id | ^^\nGrow_Id | 0\nName | ^^Elektronik\nWorldlock_balance | 0\n";
			sendData(6, (char*)x.c_str(), x.length());
			string y = "action|quit\n";
			sendData(3, (char*)y.c_str(), y.length());
			cout << endl;
			string asdf = "0400000001000000FFFFFFFF0000000008000000000000000000000000000000000000000000000000000000000000000000000000000000400000000600020E0000004F6E53656E64546F5365727665720109ED4200000209834CED00030910887F0104020D0000003230392E35392E3139302E347C05090100000000C";
			//asdf = "0400000001000000FFFFFFFF000000000800000000000000000000000000000000000000000000000000000000000000000000000000000040000000060002220000004F6E53757065724D61696E53746172744163636570744C6F676F6E464232313131330109ED4200000209834CED00030910887F0104020D0000003230392E35392E3139302E347C05090100000000C";
			ENetPacket * packet = enet_packet_create(0,
				asdf.length()/2,
				ENET_PACKET_FLAG_RELIABLE);
			for (int i = 0; i < asdf.length(); i += 2)
			{
				char x = ch2n(asdf[i]);
				x = x << 4;
				x += ch2n(asdf[i + 1]);
				memcpy(packet->data + (i / 2), &x, 1);
			}
			enet_peer_send(peer, 0, packet);
			enet_host_flush(server);
			/* Clean up the packet now that we're done using it. */
			//enet_packet_destroy(event.packet);
			//sendData(7, 0, 0);
			int messageType = GetMessageTypeFromPacket(event.packet);
			//cout << "Packet type is " << messageType << endl;
			//cout << (event->packet->data+4) << endl;
			WorldInfo* world = getPlyersWorld(peer);
			switch (messageType) {
			case 2:
			{
				//cout << GetTextPointerFromPacket(event.packet) << endl;
				string cch = GetTextPointerFromPacket(event.packet);
				string str = cch.substr(cch.find("text|") + 5, cch.length() - cch.find("text|") - 1);
				if (cch.find("action|wrench") == 0) {
					vector<string> ex = explode("|", cch);
					int id = stoi(ex[3]);

					ENetPeer* currentPeer;
					for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
					{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
							continue;

						if (isHere(peer, currentPeer)) {
							if (((PlayerInfo*)(currentPeer->data))->netID == id) {
								string name = ((PlayerInfo*)(currentPeer->data))->displayName;
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\nadd_label_with_icon|big|" + name + " `w(`2X`w)|left|18|\nadd_spacer|\nadd_textbox|`9Gems: `2X|\nadd_spacer|small|\nadd_button|chc0|`wContinue|\n"));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}

						}

					}
				}
				if (cch.find("action|respawn") == 0)
				{
					int x = 3040;
					int y = 736;

					if (!world) continue;

					for (int i = 0; i < world->width*world->height; i++)
					{
						if (world->items[i].foreground == 6) {
							x = (i%world->width) * 32;
							y = (i / world->width) * 32;
						}
					}
					{
						PlayerMoving data;
						data.packetType = 0x0;
						data.characterState = 0x924; // animation
						data.x = x;
						data.y = y;
						data.punchX = -1;
						data.punchY = -1;
						data.XSpeed = 0;
						data.YSpeed = 0;
						data.netID = ((PlayerInfo*)(peer->data))->netID;
						data.plantingTree = 0x0;
						SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
					}
					
					{
						int x = 3040;
						int y = 736;

						for (int i = 0; i < world->width*world->height; i++)
						{
							if (world->items[i].foreground == 6) {
								x = (i%world->width) * 32;
								y = (i / world->width) * 32;
							}
						}
						GamePacket p2 = packetEnd(appendFloat(appendString(createPacket(), "OnSetPos"), x,y));
						memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
						ENetPacket * packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet2);
						delete p2.data;
						//enet_host_flush(server);
					}
					{
						int x = 3040;
						int y = 736;

						for (int i = 0; i < world->width*world->height; i++)
						{
							if (world->items[i].foreground == 6) {
								x = (i%world->width) * 32;
								y = (i / world->width) * 32;
							}
						}
						GamePacket p2 = packetEnd(appendIntx(appendString(createPacket(), "OnSetFreezeState"), 0));
						memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
						ENetPacket * packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet2);
						delete p2.data;
						//enet_host_flush(server);
					}
#ifdef TOTAL_LOG
					cout << "Respawning... " << endl;
#endif
				}
				if (cch.find("action|growid") == 0)
				{
#ifndef REGISTRATION
					{
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Registration is not supported yet!"));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
						//enet_host_flush(server);
					}
#endif
#ifdef REGISTRATION
						//GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`w" + itemDefs.at(id).name + "``|left|" + std::to_string(id) + "|\n\nadd_spacer|small|\nadd_textbox|" + itemDefs.at(id).description + "|left|\nadd_spacer|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wGet a GrowID``|left|206|\n\nadd_spacer|small|\nadd_textbox|A `wGrowID `wmeans `oyou can use a name and password to logon from any device.|\nadd_spacer|small|\nadd_textbox|This `wname `owill be reserved for you and `wshown to other players`o, so choose carefully!|\nadd_text_input|username|GrowID||30|\nadd_text_input_password|password|Password||100|\nadd_text_input_password|passwordverify|Password Verify||100|\nadd_textbox|Your `wemail address `owill only be used for account verification purposes and won't be spammed or shared. If you use a fake email, you'll never be able to recover or change your password.|\nadd_text_input|email|Email||100|\nadd_textbox|Your `wDiscord ID `owill be used for secondary verification if you lost access to your `wemail address`o! Please enter in such format: `wdiscordname#tag`o. Your `wDiscord Tag `ocan be found in your `wDiscord account settings`o.|\nadd_text_input|discord|Discord||100|\nend_dialog|register|Cancel|Get My GrowID!|\n"));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
#endif
				}
				if (cch.find("action|store") == 0)
					if (((PlayerInfo*)(peer->data))->haveGrowId == true)
					{
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label|small|`wWelcome to the `bGrowtopiaFX `wStore|left|\nadd_smalltext|`wTap the item you'd like more info on. Want to get `1VIP `wstatus? Any Gems/Level purchase or `rMini-Moderator `wStatus Click Purchase `4in-game assets|\nadd_spacer|small|\nadd_button|items|`wPurchase `9in-game items|\nadd_button|store|`wPurchase `4in-game assets|\nend_dialog|chc0|Close|"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
			    }
				if (cch.find("action|AccountSecuritylocation|pausemenu") == 0)
					if (((PlayerInfo*)(peer->data))->haveGrowId == true)
					{
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label|big|`5Account-Security|left|1424|\nadd_space|small|\nadd_button|changepass|`wChange `4Password|\nadd_url_button||`wChange `4Password `5(`1In Website`5)|noflags|https://www.growtopiafx.eu|Open the Link?|0|0|\nadd_spacer|small|\nadd_button|2step|`wAdd `22-Step Verification|\nadd_spacer|small|\nend_dialog|chc0|Cancel|"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
			    }
				if (cch.find("action|info") == 0)
				{
					std::stringstream ss(cch);
					std::string to;
					int id = -1;
					int count = -1;
					while (std::getline(ss, to, '\n')) {
						vector<string> infoDat = explode("|", to);
						if (infoDat.size() == 3) {
							if (infoDat[1] == "itemID") id = atoi(infoDat[2].c_str());
							if (infoDat[1] == "count") count = atoi(infoDat[2].c_str());
						}
					}
					if (id == -1 || count == -1) continue;
					if (itemDefs.size() < id || id < 0) continue;
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`w"+ itemDefs.at(id).name +"``|left|"+std::to_string(id)+"|\n\nadd_spacer|small|\nadd_textbox|"+ itemDefs.at(id).description +"|left|\nadd_spacer|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
					ENetPacket * packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);

					//enet_host_flush(server);
					delete p.data;
				}
				if (cch.find("action|dialog_return") == 0)
				{
					std::stringstream ss(cch);
					std::string to;
					string btn = "";
					bool isRegisterDialog = false;
					bool isFindDialog = false;
					string username = "";
					string password = "";
					string passwordverify = "";
					string email = "";
					string discord = "";
					string itemFind = "";
					while (std::getline(ss, to, '\n')) {
						vector<string> infoDat = explode("|", to);
						if (infoDat.size() == 2) {
							if (infoDat[0] == "buttonClicked") btn = infoDat[1];
							if (infoDat[0] == "dialog_name" && infoDat[1] == "register")
							{
								isRegisterDialog = true;
							}
							if (infoDat[0] == "dialog_name" && infoDat[1] == "searchitem1337")
							{
								isFindDialog = true;
							}
							if (infoDat[0] == "dialog_name" && infoDat[1] == "findid")
							{
								isFindDialog = true;
							}
							if (isFindDialog) {
								if (infoDat[0] == "item") itemFind = infoDat[1];
							}
							if (isRegisterDialog) {
								if (infoDat[0] == "username") username = infoDat[1];
								if (infoDat[0] == "password") password = infoDat[1];
								if (infoDat[0] == "passwordverify") passwordverify = infoDat[1];
								if (infoDat[0] == "email") email = infoDat[1];
								if (infoDat[0] == "discord") discord = infoDat[1];
							}
						}
					}

					if (btn.substr(0, 5) == "found") {
						PlayerInventory inventory;
						InventoryItem item;
						item.itemID = atoi(btn.substr(5, btn.length()).c_str());
						item.itemCount = 200;
						inventory.items.push_back(item);
						item.itemCount = 1;
						item.itemID = 18;
						inventory.items.push_back(item);
						item.itemID = 32;
						inventory.items.push_back(item);
						sendInventory(peer, inventory);
					}

					if (btn == "worldPublic") if (((PlayerInfo*)(peer->data))->rawName == getPlyersWorld(peer)->owner) getPlyersWorld(peer)->isPublic = true;
					if(btn == "worldPrivate") if (((PlayerInfo*)(peer->data))->rawName == getPlyersWorld(peer)->owner) getPlyersWorld(peer)->isPublic = false;
					if (isFindDialog && btn.substr(0, 4) == "tool") {
						int proitem = atoi(str.substr(6, cch.length() - 6 - 1).c_str());
						if (proitem == 1874 || proitem == 1876 || proitem == 1986 || proitem == 2970 || proitem == 1780 || proitem == 1782 || proitem == 1784 || proitem == 7734 || proitem == 5026)
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wThe `9Legendary Wizard`w has invited you to come to `2LEGEND`w!``|left|1790|\n\nadd_spacer|small|\nadd_label_with_icon|small|set_default_color|`o\n\nadd_label_with_icon|big|`wThe `4Ring Master`w has invited you to come to `2CARNIVAL`w!``|left|1900|\n\nadd_spacer|small|\nadd_label_with_icon|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							//enet_host_flush(server);
							delete p.data;
						}
						else {
							string id = to.substr(0, to.find("|"));
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2/find`w] - `9Item id: `5" + id + " `9Has been added to your inventory."));
							ENetPacket* packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet2);
							//enet_host_flush(server);
							delete p2.data;
						}
						int Id = atoi(btn.substr(4, btn.length() - 4).c_str());
						size_t invsize = 200;
						if (((PlayerInfo*)(peer->data))->inventory.items.size() == invsize) {
							PlayerInventory inventory;
							InventoryItem item;
							item.itemID = Id;
							item.itemCount = 200;
							inventory.items.push_back(item);
							item.itemCount = 1;
							item.itemID = 18;
							inventory.items.push_back(item);
							item.itemID = 32;
							inventory.items.push_back(item);
							((PlayerInfo*)(peer->data))->inventory = inventory;
						}

						else {
							InventoryItem item;
							item.itemID = Id;
							item.itemCount = 200;
							((PlayerInfo*)(peer->data))->inventory.items.push_back(item);
						}
						sendInventory(peer, ((PlayerInfo*)(peer->data))->inventory);
					}
					else if (isFindDialog) {
						string itemLower2;
						vector<ItemDefinition> itemDefsfind;
						for (char c : itemFind) if (c < 0x20 || c>0x7A) goto SKIPFind;
						if (itemFind.length() < 3) goto SKIPFind3;
						for (const ItemDefinition& item : itemDefs)
						{
							string itemLower;
							for (char c : item.name) if (c < 0x20 || c>0x7A) goto SKIPFind2;
							if (!(item.id % 2 == 0)) goto SKIPFind2;
							itemLower2 = item.name;
							std::transform(itemLower2.begin(), itemLower2.end(), itemLower2.begin(), ::tolower);
							if (itemLower2.find(itemLower) != std::string::npos) {
								itemDefsfind.push_back(item);
							}
						SKIPFind2:;
						}
					SKIPFind3:;
						string listMiddle = "";
						string listFull = "";

						for (const ItemDefinition& item : itemDefsfind)
						{
							string kys = item.name;
							std::transform(kys.begin(), kys.end(), kys.begin(), ::tolower);
							string kms = itemFind;
							std::transform(kms.begin(), kms.end(), kms.begin(), ::tolower);
							if (kys.find(kms) != std::string::npos)
								listMiddle += "add_button_with_icon|tool" + to_string(item.id) + "|`$" + item.name + "``|left|" + to_string(item.id) + "||\n";
						}
						if (itemFind.length() < 3) {
							listFull = "add_textbox|`4Word is less than 3 characters!``|\nadd_spacer|small|\n";
							showWrong(peer, listFull, itemFind);
						}
						else if (itemDefsfind.size() == 0) {
							//listFull = "add_textbox|`4Found no item match!``|\nadd_spacer|small|\n";
							showWrong(peer, listFull, itemFind);

						}
						else {
							GamePacket fff = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`wFound item : " + itemFind + "``|left|6016|\nadd_spacer|small|\nadd_textbox|Enter a word below to find the item|\nadd_text_input|item|Item Name||20|\nend_dialog|findid|Cancel|Find the item!|\nadd_spacer|big|\n" + listMiddle + "add_quick_exit|\n"));
							ENetPacket* packetd = enet_packet_create(fff.data,
								fff.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packetd);

							//enet_host_flush(server);
							delete fff.data;
						}
					}
				SKIPFind:;
#ifdef REGISTRATION
					if (isRegisterDialog) {

						int regState = PlayerDB::playerRegister(username, password, passwordverify, email, discord);
						if (regState == 1) {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wGrowID GET!``|left|206|\n\nadd_spacer|small|\nadd_label|small|A `wGrowID ``with the log on of `w" + username + " ``and the password of `w" + password + " ``created. Write them down, they will be required to log on from now.|left|\nend_dialog|sasasa|Continue|"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);

							//enet_host_flush(server);
							delete p.data;
							GamePacket p9 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`eYour account was created!"));
							ENetPacket* packet9 = enet_packet_create(p9.data,
								p9.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet9);
							delete p9.data;
							GamePacket p7 = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), 0));
							ENetPacket* packet7 = enet_packet_create(p7.data,
								p7.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet7);
							GamePacket p3 = packetEnd(appendString(appendString(appendInt(appendString(createPacket(), "SetHasGrowID"), 1), username), password));
							ENetPacket* packet3 = enet_packet_create(p3.data,
								p3.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet3);

							//enet_host_flush(server);
							delete p3.data;
							string nam1e = "```0" + username;
							((PlayerInfo*)(event.peer->data))->displayName = username;
							((PlayerInfo*)(event.peer->data))->tankIDName = username;
							((PlayerInfo*)(event.peer->data))->tankIDPass = password;
							((PlayerInfo*)(event.peer->data))->rawName = PlayerDB::getProperName(((PlayerInfo*)(event.peer->data))->tankIDName);
							((PlayerInfo*)(event.peer->data))->haveGrowId = true;
							GamePacket p4 = packetEnd(appendString(appendString(createPacket(), "OnNameChanged"), nam1e));
							memcpy(p4.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
							ENetPacket* packet4 = enet_packet_create(p4.data,
								p4.len,
								ENET_PACKET_FLAG_RELIABLE);
							string text = "action|play_sfx\nfile|audio/piano_nice.wav\ndelayMS|0\n";
							BYTE* data = new BYTE[5 + text.length()];
							BYTE zero = 0;
							int type = 3;
							memcpy(data, &type, 4);
							memcpy(data + 4, text.c_str(), text.length());
							memcpy(data + 4 + text.length(), &zero, 1);
							ENetPacket* packet2 = enet_packet_create(data,
								5 + text.length(),
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet2);

							//enet_host_flush(server);
							ENetPeer* currentPeer;
							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									enet_peer_send(currentPeer, 0, packet4);
								}
							}
							delete p4.data;
						}

						else if(regState==-1) {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`rAccount creation has failed, because it already exists!``"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						else if (regState == -2) {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`rAccount creation has failed, because the name is too short!``"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						else if (regState == -3) {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Passwords mismatch!``"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						else if (regState == -4) {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Account creation has failed, because email address is invalid!``"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						else if (regState == -5) {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Account creation has failed, because Discord ID is invalid!``"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
					}
					if (btn == "store") {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wWelcome to Our Store!|left|1430|\nadd_spacer|small|\nadd_button|pmods|`wPurchase `rMini-Moderator|\nadd_button|pvips|`wPurchase `1VIP|\nadd_button|pgems|`wPurchase `9Gems|\nadd_button|plvls|`wPurchase `3Levels|\nadd_spacer|small|\nadd_button|mainstore|`wBack|\nadd_button|chc0|`wClose|\n"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						//enet_host_flush(server);
						delete p.data;
					}
					if (btn == "mainstore") {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label|small|`wWelcome to the `bGrowtopiaFX `wStore|left|\nadd_smalltext|`wTap the item you'd like more info on. Want to get `1VIP `wstatus? Any Gems/Level purchase or `rMini-Moderator `wStatus Click Purchase `4in-game assets|\nadd_spacer|small|\nadd_button|items|`wPurchase `9in-game items|\nadd_button|store|`wPurchase `4in-game assets|\nend_dialog|chc0|Close|"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
					}
					if (btn == "items") {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`wWelcome to our shop!|left|1430|\nadd_spacer|small|\nadd_textbox|`rPlease choose item that you want to purchase!|\nadd_spacer|small|\nadd_label_with_icon|small|`6Special Items`4:|left|7912|\nset_labelXMult|1.2\nadd_button_with_icon|aac||staticBlueFrame|5078|250000|\nadd_button_with_icon|fye||staticBlueFrame|7912|5000000|\nadd_button_with_icon|rfs||staticBlueFrame|5480|50000|\nadd_button_with_icon||END_LIST|noflags|0|0|\nadd_spacer|small|\nadd_label_with_icon|small|`6Rare Items`4:|left|8286|\nset_labelXMult|1.2\nadd_button_with_icon|fcs||staticBlueFrame|1204|10000|\nadd_button_with_icon|dav||staticBlueFrame|8286|100000|\nadd_button_with_icon||END_LIST|noflags|0|0|\nadd_spacer|small|\nadd_label_with_icon|small|`6Carnival Items`4:|left|1900|\nset_labelXMult|1.2\nadd_button_with_icon|wsd||staticBlueFrame|1876|7500|\nadd_button_with_icon|frc||staticBlueFrame|1874|7500|\nadd_button_with_icon|grn||staticBlueFrame|1986|7500|\nadd_button_with_icon||END_LIST|noflags|0|0|\nadd_spacer|small|\nadd_label_with_icon|small|`6Title Items`4:|left|3130|\nset_labelXMult|1.2\nadd_button_with_icon|drt||staticBlueFrame|3130|125000|\nadd_button_with_icon||END_LIST|noflags|0|0|\nadd_spacer|small|\nadd_button|chc0|`wBack|\n"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
					}
					if (btn == "pmods") {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wPurchase Mini-Moderator|left|18|\nadd_smalltext|`4Make sure to read this information clearly.|\nadd_spacer|small|\nadd_smalltext|`oPrice: `15Diamond Locks|\nadd_smalltext|`oDurations: `w[`4~`w]|\nadd_smalltext|`oStock: `w[`4~`w]|\nadd_spacer|small|\nadd_textbox|`6Rules|\nadd_spacer|small|\nadd_smalltext|`e1. `rDo not abuse your powers or it will result into an ip-ban!|\nadd_smalltext|`e2. `rBefore applying punishment please provide proof in discord channel: #punish-proof.|\nadd_smalltext|`e3. `rPlease follow the moderator-rules in discord.|\nadd_spacer|small|\nadd_textbox|`6Commands|\nadd_spacer|small|\nadd_smalltext|`eAll commands will be displayed in /ahelp.|\nadd_spacer|small|\nadd_textbox|`6How to Purchase|\nadd_spacer|small|\nadd_smalltext|`oTo `2Successfully `oPurchase the `rMini-Moderator `oRank, Just follow the simple steps, Log onto real growtopia, then goto world: `wGTFXDEPOSIT`o, Then deposit the required amount of locks, then just leave the world. Make sure to include `w#BUYMINIMOD`o.|\nadd_spacer|small|\nadd_textbox|`6When will I receive my Purchase|\nadd_spacer|small|\nadd_smalltext|`oYou will receive your requested purchase within `b24Hours`w! If your purchase has not been submited, Report to Staff right away!|\nadd_spacer|small|\nadd_button|store|`wBack|\nadd_button|chc0a|`wClose|\n"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						//enet_host_flush(server);
						delete p.data;
					}
					if (btn == "pvips") {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wPurchase VIP|left|18|\nadd_smalltext|`4Make sure to read this information clearly.|\nadd_spacer|small|\nadd_smalltext|`oPrice: `12Diamond Locks|\nadd_smalltext|`oDurations: `w[`4~`w]|\nadd_smalltext|`oStock: `w[`4~`w]|\nadd_spacer|small|\nadd_textbox|`6Rules|\nadd_spacer|small|\nadd_smalltext|`e1. `rDo not abuse your powers or it will result into an ip-ban!|\nadd_smalltext|`e2. `rPlease follow the vip-rules in discord.|\nadd_spacer|small|\nadd_textbox|`6Commands|\nadd_spacer|small|\nadd_smalltext|`eAll commands will be displayed in /vhelp.|\nadd_spacer|small|\nadd_textbox|`6How to Purchase|\nadd_spacer|small|\nadd_smalltext|`oTo `2Successfully `oPurchase the `1VIP `oRank, Just follow the simple steps, Log onto real growtopia, then goto world: `wGTFXDEPOSIT`o, Then deposit the required amount of locks, then just leave the world. Make sure to include `w#BUYVIP`o.|\nadd_spacer|small|\nadd_textbox|`6When will I receive my Purchase|\nadd_spacer|small|\nadd_smalltext|`oYou will receive your requested purchase within `b24Hours`w! If your purchase has not been submited, Report to Staff right away!|\nadd_spacer|small|\nadd_button|store|`wBack|\nadd_button|chc0a|`wClose|\n"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						//enet_host_flush(server);
						delete p.data;
					}
					if (btn == "pgems") {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wPurchase Gems|left|18|\nadd_smalltext|`4Make sure to read this information clearly.|\nadd_spacer|small|\nadd_smalltext|`oPrice: `93000/1World Lock|\nadd_smalltext|`oDurations: `w[`4~`w]|\nadd_smalltext|`oStock: `w[`4~`w]|\nadd_spacer|small|\nadd_textbox|`6Rules|\nadd_spacer|small|\nadd_smalltext|`e1. `rDo not Sell your gems or it will result into an ip-ban!|\nadd_smalltext|`e2. `rDo not scam with your purchased gems!|\nadd_smalltext|`e3.`r If you want to donate someone gems it does not count as ILLEGAL!|\nadd_spacer|small|\nadd_spacer|small|\nadd_textbox|`6How to Purchase|\nadd_spacer|small|\nadd_smalltext|`oTo `2Successfully `oPurchase the `9Gems`o, Just follow the simple steps, Log onto real growtopia, then goto world: `wGTFXDEPOSIT`o, Then deposit the required amount of locks, then just leave the world. Make sure to include `w#BUYGEMS`o.|\nadd_spacer|small|\nadd_textbox|`6When will I receive my Purchase|\nadd_spacer|small|\nadd_smalltext|`oYou will receive your requested purchase within `b24Hours`w! If your purchase has not been submited, Report to Staff right away!|\nadd_spacer|small|\nadd_button|store|`wBack|\nadd_button|chc0a|`wClose|\n"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						//enet_host_flush(server);
						delete p.data;
					}
					if (btn == "plvls") {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wPurchase Levels|left|18|\nadd_smalltext|`4Make sure to read this information clearly.|\nadd_spacer|small|\nadd_smalltext|`oPrice: `95/1World Lock|\nadd_smalltext|`oDurations: `w[`4~`w]|\nadd_smalltext|`oStock: `w[`4~`w]|\nadd_spacer|small|\nadd_textbox|`6How to Purchase|\nadd_spacer|small|\nadd_smalltext|`oTo `2Successfully `oPurchase the `3Levels`w, Just follow the simple steps, Log onto real growtopia, then goto world: `wGTFXDEPOSIT`o, Then deposit the required amount of locks, then just leave the world. Make sure to include `w#BUYLEVELS`o.|\nadd_spacer|small|\nadd_textbox|`6When will I receive my Purchase|\nadd_spacer|small|\nadd_smalltext|`oYou will receive your requested purchase within `b24Hours`w! If your purchase has not been submited, Report to Staff right away!|\nadd_spacer|small|\nadd_button|store|`wBack|\nadd_button|chc0a|`wClose|\n"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						//enet_host_flush(server);
						delete p.data;
					}
					if (btn == "fye")
					{
						if (((PlayerInfo*)(peer->data))->boughtFYE == false)
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`6Special Items|left|7912|\nadd_spacer|small|\nadd_textbox|`rMake sure its the correct item!|\nadd_spacer|small|\nadd_textbox|`4You are about to purchase `9War Hammer of Darkness!|\nadd_textbox|`2This item Contains: `wWar Hammer of Darkness + `9Special Commands`w: `2/ssb`w and also 2-18 gems with Breaking and `8Custom rank`w: `9S`4P`2E`8C`1I`6A`bL`w!|\nadd_spacer|small|\nadd_button|yesfye|`9Purchase For `25000000 `9Gems.|\nadd_spacer|small|\nadd_button|items|`wBack|\nadd_button|chc0|`wClose|\n "));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						else
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`6Special Items|left|7912|\nadd_smalltext|`4NOTE: `wIf you are refunding the items, You will get half of the Gems back!|\nadd_spacer|small|\nadd_textbox|`rMake sure its the correct item!|\nadd_spacer|small|\nadd_textbox|`4You are about to Refunding `9War Hammer of Darkness!|\nadd_textbox|`2This item Contains: `wWar Hammer of Darkness + `9Special Commands`w: `2/ssb`w and also 2-18 gems with Breaking and `8Custom rank`w: `9S`4P`2E`8C`1I`6A`bL`w!|\nadd_spacer|small|\nadd_button|refundfye| `9-Refund the Item- |\nadd_spacer|small|\nadd_button|items|`wBack|\nadd_button|chc0|`wClose|\n "));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
					}
					if (btn == "aac")
					{
						if (((PlayerInfo*)(peer->data))->boughtAAC == false)
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`6Special Items|left|5078|\nadd_spacer|small|\nadd_textbox|`rMake sure its the correct item!|\nadd_spacer|small|\nadd_textbox|`4You are about to purchase `9Ancestral items!|\nadd_textbox|`2This item contains: `wAncestral Items + 2-9 gems for breaking and `4Dr. `wName!|\nadd_spacer|small|\nadd_button|yesanc|`9Purchase For `2250000 `9Gems.|\nadd_spacer|small|\nadd_button|items|`wBack|\nadd_button|chc0|`wClose|\n"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						else
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`6Special Items|left|5078|\nadd_smalltext|`4NOTE: `wIf you are refunding the items, You will get half of the Gems back!|\nadd_spacer|small|\nadd_textbox|`rMake sure its the correct item!|\nadd_spacer|small|\nadd_textbox|`4You are about to Refunding `9Ancestral items!|\nadd_textbox|`2This item contains: `wAncestral Items + 2-9 gems for breaking!|\nadd_spacer|small|\nadd_button|yesanc| `9-Refund the Item- |\nadd_spacer|small|\nadd_button|items|`wBack|\nadd_button|chc0|`wClose|\n"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
					}
					if (btn == "rfs")
					{
						if (((PlayerInfo*)(peer->data))->boughtRFS == false)
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`6Special Items|left|5480|\nadd_spacer|small|\nadd_textbox|`rMake sure its the correct item!|\nadd_spacer|small|\nadd_textbox|`4You are about to purchase `9Rayman's Fists!|\nadd_textbox|`2This item contains: `wRayman's Fists!|\nadd_spacer|small|\nadd_button|yesrfs|`9Purchase For `230000 `9Gems.|\nadd_spacer|small|\nadd_button|items|`wBack|\nadd_button|chc0|Close|\n"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						else
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`6Special Items|left|5480|\nadd_smalltext|`4NOTE: `wIf you are refunding the items, You will get half of the Gems back!|\nadd_spacer|small|\nadd_textbox|`rMake sure its the correct item!|\nadd_spacer|small|\nadd_textbox|`4You are about to Refunding `9Rayman's Fists!|\nadd_textbox|`2This item contains: `wRayman's Fists!|\nadd_spacer|small|\nadd_button|refundrfs| `9-Refund this item- |\nadd_spacer|small|\nadd_button|items|`wBack|\nadd_button|chc0|Close|\n"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
					}
					if (btn == "wsd")
					{
						if (((PlayerInfo*)(peer->data))->boughtWSD == false)
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`6Carnival Items|left|1876|\nadd_spacer|small|\nadd_textbox|`rMake sure its the correct item!|\nadd_spacer|small|\nadd_textbox|`4You are about to purchase `9Ring of Winds!|\nadd_textbox|`2This item contains: `wRing of Winds + Cloudy contrail!|\nadd_spacer|small|\nadd_button|yeswsd|`9Purchase For `27500 `9Gems.|\nadd_spacer|small|\nadd_button|items|`wBack|\nadd_button|chc0|Close|\n"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						else
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`6Carnival Items|left|1876|\nadd_smalltext|`4NOTE: `wIf you are refunding the items, You will get half of the Gems back!|\nadd_spacer|small|\nadd_textbox|`rMake sure its the correct item!|\nadd_spacer|small|\nadd_textbox|`4You are about to Refunding `9Ring of Winds!|\nadd_textbox|`2This item contains: `wRing of Winds!|\nadd_spacer|small|\nadd_button|refundwsd| `9-Refund this item- |\nadd_spacer|small|\nadd_button|items|`wBack|\nadd_button|chc0|Close|\n"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
					}
					if (btn == "grn")
					{
						if (((PlayerInfo*)(peer->data))->boughtGRN == false)
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`6Carnival Items|left|1986|\nadd_spacer|small|\nadd_textbox|`rMake sure its the correct item!|\nadd_spacer|small|\nadd_textbox|`4You are about to purchase `9Gemini Ring!|\nadd_textbox|`2This item contains: `wGemini Ring + Special clone of yourself!|\nadd_spacer|small|\nadd_button|yesgrn|`9Purchase For `27500 `9Gems.|\nadd_spacer|small|\nadd_button|items|`wBack|\nadd_button|chc0|Close|\n"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						else
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`6Carnival Items|left|1986|\nadd_smalltext|`4NOTE: `wIf you are refunding the items, You will get half of the Gems back!|\nadd_spacer|small|\nadd_textbox|`rMake sure its the correct item!|\nadd_spacer|small|\nadd_textbox|`4You are about to Refunding `9Gemini Ring!|\nadd_textbox|`2This item contains: `wGemini Ring!|\nadd_spacer|small|\nadd_button|refundgrn| `9-Refund this item- |\nadd_spacer|small|\nadd_button|items|`wBack|\nadd_button|chc0|Close|\n"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
					}
					if (btn == "frc")
					{
						if (((PlayerInfo*)(peer->data))->boughtFRC == false)
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`6Carnival Items|left|1874|\nadd_spacer|small|\nadd_textbox|`rMake sure its the correct item!|\nadd_spacer|small|\nadd_textbox|`4You are about to purchase `9Ring of Force!|\nadd_textbox|`2This item contains: `wRing of Force + 2x More XP When breaking also Contains special explosion effect!|\nadd_spacer|small|\nadd_button|yesfrc|`9Purchase For `27500 `9Gems.|\nadd_spacer|small|\nadd_button|items|`wBack|\nadd_button|chc0|Close|\n"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						else
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`6Carnival Items|left|1874|\nadd_smalltext|`4NOTE: `wIf you are refunding the items, You will get half of the Gems back!|\nadd_spacer|small|\nadd_textbox|`rMake sure its the correct item!|\nadd_spacer|small|\nadd_textbox|`4You are about to Refunding `9Ring of Force!|\nadd_textbox|`2This item contains: `wRing of Force!|\nadd_spacer|small|\nadd_button|refundfrc| `9-Refund this item- |\nadd_spacer|small|\nadd_button|items|`wBack|\nadd_button|chc0|Close|\n"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
					}
					if (btn == "dav")
					{
						if (((PlayerInfo*)(peer->data))->boughtFRC == false)
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`6Rare Items|left|8286|\nadd_spacer|small|\nadd_textbox|`rMake sure its the correct item!|\nadd_spacer|small|\nadd_textbox|`4You are about to purchase `9Da Vinc Wings!|\nadd_textbox|`2This item contains: `wDa Vinci Wings!|\nadd_spacer|small|\nadd_button|yesdav|`9Purchase For `2100000 `9Gems.|\nadd_spacer|small|\nadd_button|items|`wBack|\nadd_button|chc0|Close|\n"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						else
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`6Rare Items|left|8286|\nadd_smalltext|`4NOTE: `wIf you are refunding the items, You will get half of the Gems back!|\nadd_spacer|small|\nadd_textbox|`rMake sure its the correct item!|\nadd_spacer|small|\nadd_textbox|`4You are about to Refunding `9Da Vinci Wings!|\nadd_textbox|`2This item contains: `wDa Vinci Wings!|\nadd_spacer|small|\nadd_button|refunddav| `9-Refund this item- |\nadd_spacer|small|\nadd_button|items|`wBack|\nadd_button|chc0|Close|\n"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
					}
					if (btn == "fcs")
					{
						if (((PlayerInfo*)(peer->data))->boughtFRC == false)
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`6Rare Items|left|1204|\nadd_spacer|small|\nadd_textbox|`rMake sure its the correct item!|\nadd_spacer|small|\nadd_textbox|`4You are about to purchase `9Focused Eyes!|\nadd_textbox|`2This item contains: `wFocused Eyes!|\nadd_spacer|small|\nadd_button|yesfcs|`9Purchase For `210000 `9Gems.|\nadd_spacer|small|\nadd_button|items|`wBack|\nadd_button|chc0|Close|\n"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						else
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`6Rare Items|left|1204|\nadd_smalltext|`4NOTE: `wIf you are refunding the items, You will get half of the Gems back!|\nadd_spacer|small|\nadd_textbox|`rMake sure its the correct item!|\nadd_spacer|small|\nadd_textbox|`4You are about to Refunding `9Focused Eyes!|\nadd_textbox|`2This item contains: `wFocused Eyes!|\nadd_spacer|small|\nadd_button|refundfcs| `9-Refund this item- |\nadd_spacer|small|\nadd_button|items|`wBack|\nadd_button|chc0|Close|\n"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
					}
					if (btn == "drt")
					{
						if (((PlayerInfo*)(peer->data))->boughtFRC == false)
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`6Title Items|left|3130|\nadd_spacer|small|\nadd_textbox|`rMake sure its the correct item!|\nadd_spacer|small|\nadd_textbox|`4You are about to purchase `9Dr. Tittle!|\nadd_textbox|`2This item contains: `wDr. Title + Special name: `4Dr. `w<player> !|\nadd_spacer|small|\nadd_button|yesdrt|`9Purchase For `2125000 `9Gems.|\nadd_spacer|small|\nadd_button|items|`wBack|\nadd_button|chc0|Close|\n"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						else
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`6Title Items|left|3130|\nadd_smalltext|`4NOTE: `wIf you are refunding the items, You will get half of the Gems back!|\nadd_spacer|small|\nadd_textbox|`rMake sure its the correct item!|\nadd_spacer|small|\nadd_textbox|`4You are about to Refunding `9Dr. Title!|\nadd_textbox|`2This item contains: `wDr. Title + Special name: `4Dr. `w<player> !|\nadd_spacer|small|\nadd_button|refunddrt| `9-Refund this item- |\nadd_spacer|small|\nadd_button|items|`wBack|\nadd_button|chc0|Close|\n"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
					}
					if (btn == "yesfye") {
						if (((PlayerInfo*)(peer->data))->gem > 4999999)
						{

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "`wSuccessfully `wPurchasing `5War Hammer of Darkness"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;

							((PlayerInfo*)(peer->data))->gem = ((PlayerInfo*)(peer->data))->gem - 5000000;
							GamePacket psa = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
							ENetPacket* packetsa = enet_packet_create(psa.data, psa.len, ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packetsa);

							delete psa.data;


							((PlayerInfo*)(peer->data))->boughtFYE = true;

							std::ifstream ifff("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json");


							if (ifff.fail()) {
								ifff.close();


							}
							if (ifff.is_open()) {
							}
							json j;
							ifff >> j; //load


							j["boughtFYE"] = ((PlayerInfo*)(peer->data))->boughtFYE; //edit




							std::ofstream o("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json"); //save
							if (!o.is_open()) {
								cout << GetLastError() << endl;
								_getch();
							}

							o << j << std::endl;


							PlayerInventory inventory;
							InventoryItem item;
							item.itemCount = 1;
							item.itemID = 18;
							inventory.items.push_back(item);
							item.itemCount = 1;
							item.itemID = 32;
							inventory.items.push_back(item);
							item.itemCount = 1;
							item.itemID = 7912;
							inventory.items.push_back(item);
							sendInventory(peer, inventory);


							string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
							BYTE* data = new BYTE[5 + text.length()];
							BYTE zero = 0;
							int type = 3;
							memcpy(data, &type, 4);
							memcpy(data + 4, text.c_str(), text.length()); // change memcpy here
							memcpy(data + 4 + text.length(), &zero, 1); // change memcpy here, revert to 4

							ENetPacket* packetsou = enet_packet_create(data,
								5 + text.length(),
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packetsou);

						}
						else
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`wPayment `4Declined|left|6802|\nadd_spacer|small|\nadd_textbox|`wYour Current Payment has been `4DECLINED `wThis is caused due to Not enough `9Gems`w.|\nadd_spacer|small|\nadd_button|yesfye|`wBack|\nadd_spacer|small|\nadd_button|chc0|Close|\n"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
					}
					if (btn == "yesdrt") {
						if (((PlayerInfo*)(peer->data))->gem > 124999)
						{

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "`wSuccessfully `wPurchasing `5Dr. Tittle"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;

							((PlayerInfo*)(peer->data))->gem = ((PlayerInfo*)(peer->data))->gem - 125000;
							GamePacket psa = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
							ENetPacket* packetsa = enet_packet_create(psa.data, psa.len, ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packetsa);

							delete psa.data;


							((PlayerInfo*)(peer->data))->boughtDRT = true;

							std::ifstream ifff("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json");


							if (ifff.fail()) {
								ifff.close();


							}
							if (ifff.is_open()) {
							}
							json j;
							ifff >> j; //load


							j["boughtDRT"] = ((PlayerInfo*)(peer->data))->boughtDRT; //edit




							std::ofstream o("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json"); //save
							if (!o.is_open()) {
								cout << GetLastError() << endl;
								_getch();
							}

							o << j << std::endl;


							PlayerInventory inventory;
							InventoryItem item;
							item.itemCount = 1;
							item.itemID = 18;
							inventory.items.push_back(item);
							item.itemCount = 1;
							item.itemID = 32;
							inventory.items.push_back(item);
							item.itemCount = 1;
							item.itemID = 0;
							inventory.items.push_back(item);
							sendInventory(peer, inventory);


							string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
							BYTE* data = new BYTE[5 + text.length()];
							BYTE zero = 0;
							int type = 3;
							memcpy(data, &type, 4);
							memcpy(data + 4, text.c_str(), text.length()); // change memcpy here
							memcpy(data + 4 + text.length(), &zero, 1); // change memcpy here, revert to 4

							ENetPacket* packetsou = enet_packet_create(data,
								5 + text.length(),
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packetsou);

						}
						else
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`wPayment `4Declined|left|6802|\nadd_spacer|small|\nadd_textbox|`wYour Current Payment has been `4DECLINED `wThis is caused due to Not enough `9Gems`w.|\nadd_spacer|small|\nadd_button|yesfye|`wBack|\nadd_spacer|small|\nadd_button|chc0|Close|\n"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
					}
					if (btn == "yeswsd") {
						if (((PlayerInfo*)(peer->data))->gem > 7499)
						{

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "`wSuccessfully `wPurchasing `5Ring of Winds"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;

							((PlayerInfo*)(peer->data))->gem = ((PlayerInfo*)(peer->data))->gem - 7500;
							GamePacket psa = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
							ENetPacket* packetsa = enet_packet_create(psa.data, psa.len, ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packetsa);

							delete psa.data;


							((PlayerInfo*)(peer->data))->boughtWSD = true;

							std::ifstream ifff("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json");


							if (ifff.fail()) {
								ifff.close();


							}
							if (ifff.is_open()) {
							}
							json j;
							ifff >> j; //load


							j["boughtWSD"] = ((PlayerInfo*)(peer->data))->boughtWSD; //edit




							std::ofstream o("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json"); //save
							if (!o.is_open()) {
								cout << GetLastError() << endl;
								_getch();
							}

							o << j << std::endl;


							PlayerInventory inventory;
							InventoryItem item;
							item.itemCount = 1;
							item.itemID = 18;
							inventory.items.push_back(item);
							item.itemCount = 1;
							item.itemID = 32;
							inventory.items.push_back(item);
							item.itemCount = 1;
							item.itemID = 1876;
							inventory.items.push_back(item);
							sendInventory(peer, inventory);


							string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
							BYTE* data = new BYTE[5 + text.length()];
							BYTE zero = 0;
							int type = 3;
							memcpy(data, &type, 4);
							memcpy(data + 4, text.c_str(), text.length()); // change memcpy here
							memcpy(data + 4 + text.length(), &zero, 1); // change memcpy here, revert to 4

							ENetPacket* packetsou = enet_packet_create(data,
								5 + text.length(),
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packetsou);

						}
						else
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`wPayment `4Declined|left|6802|\nadd_spacer|small|\nadd_textbox|`wYour Current Payment has been `4DECLINED `wThis is caused due to Not enough `9Gems`w.|\nadd_spacer|small|\nadd_button|yesfye|`wBack|\nadd_spacer|small|\nadd_button|chc0|Close|\n"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
					}
					if (btn == "yesrfs") {
						if (((PlayerInfo*)(peer->data))->gem > 49999)
						{

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "`wSuccessfully `wPurchasing `5Rayman's Fists"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;

							((PlayerInfo*)(peer->data))->gem = ((PlayerInfo*)(peer->data))->gem - 50000;
							GamePacket psa = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
							ENetPacket* packetsa = enet_packet_create(psa.data, psa.len, ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packetsa);

							delete psa.data;


							((PlayerInfo*)(peer->data))->boughtRFS = true;

							std::ifstream ifff("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json");


							if (ifff.fail()) {
								ifff.close();


							}
							if (ifff.is_open()) {
							}
							json j;
							ifff >> j; //load


							j["boughtRFS"] = ((PlayerInfo*)(peer->data))->boughtRFS; //edit




							std::ofstream o("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json"); //save
							if (!o.is_open()) {
								cout << GetLastError() << endl;
								_getch();
							}

							o << j << std::endl;


							PlayerInventory inventory;
							InventoryItem item;
							item.itemCount = 1;
							item.itemID = 18;
							inventory.items.push_back(item);
							item.itemCount = 1;
							item.itemID = 32;
							inventory.items.push_back(item);
							item.itemCount = 1;
							item.itemID = 5480;
							inventory.items.push_back(item);
							sendInventory(peer, inventory);


							string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
							BYTE* data = new BYTE[5 + text.length()];
							BYTE zero = 0;
							int type = 3;
							memcpy(data, &type, 4);
							memcpy(data + 4, text.c_str(), text.length()); // change memcpy here
							memcpy(data + 4 + text.length(), &zero, 1); // change memcpy here, revert to 4

							ENetPacket* packetsou = enet_packet_create(data,
								5 + text.length(),
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packetsou);

						}
						else
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`wPayment `4Declined|left|6802|\nadd_spacer|small|\nadd_textbox|`wYour Current Payment has been `4DECLINED `wThis is caused due to Not enough `9Gems`w.|\nadd_spacer|small|\nadd_button|yesrfs|`wBack|\nadd_spacer|small|\nadd_button|chc0|Close|\n"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
					}
					if (btn == "yesdav") {
						if (((PlayerInfo*)(peer->data))->gem > 99999)
						{

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "`wSuccessfully `wPurchasing `5Da Vinci Wings"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;

							((PlayerInfo*)(peer->data))->gem = ((PlayerInfo*)(peer->data))->gem - 100000;
							GamePacket psa = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
							ENetPacket* packetsa = enet_packet_create(psa.data, psa.len, ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packetsa);

							delete psa.data;


							((PlayerInfo*)(peer->data))->boughtDAV = true;

							std::ifstream ifff("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json");


							if (ifff.fail()) {
								ifff.close();


							}
							if (ifff.is_open()) {
							}
							json j;
							ifff >> j; //load


							j["boughtDAV"] = ((PlayerInfo*)(peer->data))->boughtDAV; //edit




							std::ofstream o("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json"); //save
							if (!o.is_open()) {
								cout << GetLastError() << endl;
								_getch();
							}

							o << j << std::endl;


							PlayerInventory inventory;
							InventoryItem item;
							item.itemCount = 1;
							item.itemID = 18;
							inventory.items.push_back(item);
							item.itemCount = 1;
							item.itemID = 32;
							inventory.items.push_back(item);
							item.itemCount = 1;
							item.itemID = 8286;
							inventory.items.push_back(item);
							sendInventory(peer, inventory);


							string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
							BYTE* data = new BYTE[5 + text.length()];
							BYTE zero = 0;
							int type = 3;
							memcpy(data, &type, 4);
							memcpy(data + 4, text.c_str(), text.length()); // change memcpy here
							memcpy(data + 4 + text.length(), &zero, 1); // change memcpy here, revert to 4

							ENetPacket* packetsou = enet_packet_create(data,
								5 + text.length(),
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packetsou);

						}
						else
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`wPayment `4Declined|left|6802|\nadd_spacer|small|\nadd_textbox|`wYour Current Payment has been `4DECLINED `wThis is caused due to Not enough `9Gems`w.|\nadd_spacer|small|\nadd_button|yesrfs|`wBack|\nadd_spacer|small|\nadd_button|chc0|Close|\n"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
					}
					if (btn == "yesfcs") {
						if (((PlayerInfo*)(peer->data))->gem > 9999)
						{

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "`wSuccessfully `wPurchasing `5Focused Eyes"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;

							((PlayerInfo*)(peer->data))->gem = ((PlayerInfo*)(peer->data))->gem - 10000;
							GamePacket psa = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
							ENetPacket* packetsa = enet_packet_create(psa.data, psa.len, ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packetsa);

							delete psa.data;


							((PlayerInfo*)(peer->data))->boughtFCS = true;

							std::ifstream ifff("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json");


							if (ifff.fail()) {
								ifff.close();


							}
							if (ifff.is_open()) {
							}
							json j;
							ifff >> j; //load


							j["boughtFCS"] = ((PlayerInfo*)(peer->data))->boughtFCS; //edit




							std::ofstream o("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json"); //save
							if (!o.is_open()) {
								cout << GetLastError() << endl;
								_getch();
							}

							o << j << std::endl;


							PlayerInventory inventory;
							InventoryItem item;
							item.itemCount = 1;
							item.itemID = 18;
							inventory.items.push_back(item);
							item.itemCount = 1;
							item.itemID = 32;
							inventory.items.push_back(item);
							item.itemCount = 1;
							item.itemID = 1204;
							inventory.items.push_back(item);
							sendInventory(peer, inventory);


							string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
							BYTE* data = new BYTE[5 + text.length()];
							BYTE zero = 0;
							int type = 3;
							memcpy(data, &type, 4);
							memcpy(data + 4, text.c_str(), text.length()); // change memcpy here
							memcpy(data + 4 + text.length(), &zero, 1); // change memcpy here, revert to 4

							ENetPacket* packetsou = enet_packet_create(data,
								5 + text.length(),
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packetsou);

						}
						else
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`wPayment `4Declined|left|6802|\nadd_spacer|small|\nadd_textbox|`wYour Current Payment has been `4DECLINED `wThis is caused due to Not enough `9Gems`w.|\nadd_spacer|small|\nadd_button|yesrfs|`wBack|\nadd_spacer|small|\nadd_button|chc0|Close|\n"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
					}
					if (btn == "yesfrc") {
						if (((PlayerInfo*)(peer->data))->gem > 7499)
						{

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "`wSuccessfully `wPurchasing `5Ring of Force"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;

							((PlayerInfo*)(peer->data))->gem = ((PlayerInfo*)(peer->data))->gem - 7500;
							GamePacket psa = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
							ENetPacket* packetsa = enet_packet_create(psa.data, psa.len, ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packetsa);

							delete psa.data;


							((PlayerInfo*)(peer->data))->boughtFRC = true;

							std::ifstream ifff("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json");


							if (ifff.fail()) {
								ifff.close();


							}
							if (ifff.is_open()) {
							}
							json j;
							ifff >> j; //load


							j["boughtFRC"] = ((PlayerInfo*)(peer->data))->boughtFRC; //edit




							std::ofstream o("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json"); //save
							if (!o.is_open()) {
								cout << GetLastError() << endl;
								_getch();
							}

							o << j << std::endl;


							PlayerInventory inventory;
							InventoryItem item;
							item.itemCount = 1;
							item.itemID = 18;
							inventory.items.push_back(item);
							item.itemCount = 1;
							item.itemID = 32;
							inventory.items.push_back(item);
							item.itemCount = 1;
							item.itemID = 1874;
							inventory.items.push_back(item);
							sendInventory(peer, inventory);


							string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
							BYTE* data = new BYTE[5 + text.length()];
							BYTE zero = 0;
							int type = 3;
							memcpy(data, &type, 4);
							memcpy(data + 4, text.c_str(), text.length()); // change memcpy here
							memcpy(data + 4 + text.length(), &zero, 1); // change memcpy here, revert to 4

							ENetPacket* packetsou = enet_packet_create(data,
								5 + text.length(),
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packetsou);

						}
						else
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`wPayment `4Declined|left|6802|\nadd_spacer|small|\nadd_textbox|`wYour Current Payment has been `4DECLINED `wThis is caused due to Not enough `9Gems`w.|\nadd_spacer|small|\nadd_button|yesrfs|`wBack|\nadd_spacer|small|\nadd_button|chc0|Close|\n"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
					}
					if (btn == "yesgrn") {
						if (((PlayerInfo*)(peer->data))->gem > 7499)
						{

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "`wSuccessfully `wPurchasing `5Gemini Ring"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;

							((PlayerInfo*)(peer->data))->gem = ((PlayerInfo*)(peer->data))->gem - 7500;
							GamePacket psa = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
							ENetPacket* packetsa = enet_packet_create(psa.data, psa.len, ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packetsa);

							delete psa.data;


							((PlayerInfo*)(peer->data))->boughtGRN = true;

							std::ifstream ifff("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json");


							if (ifff.fail()) {
								ifff.close();


							}
							if (ifff.is_open()) {
							}
							json j;
							ifff >> j; //load


							j["boughtGRN"] = ((PlayerInfo*)(peer->data))->boughtGRN; //edit




							std::ofstream o("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json"); //save
							if (!o.is_open()) {
								cout << GetLastError() << endl;
								_getch();
							}

							o << j << std::endl;


							PlayerInventory inventory;
							InventoryItem item;
							item.itemCount = 1;
							item.itemID = 18;
							inventory.items.push_back(item);
							item.itemCount = 1;
							item.itemID = 32;
							inventory.items.push_back(item);
							item.itemCount = 1;
							item.itemID = 1986;
							inventory.items.push_back(item);
							sendInventory(peer, inventory);


							string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
							BYTE* data = new BYTE[5 + text.length()];
							BYTE zero = 0;
							int type = 3;
							memcpy(data, &type, 4);
							memcpy(data + 4, text.c_str(), text.length()); // change memcpy here
							memcpy(data + 4 + text.length(), &zero, 1); // change memcpy here, revert to 4

							ENetPacket* packetsou = enet_packet_create(data,
								5 + text.length(),
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packetsou);

						}
						else
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`wPayment `4Declined|left|6802|\nadd_spacer|small|\nadd_textbox|`wYour Current Payment has been `4DECLINED `wThis is caused due to Not enough `9Gems`w.|\nadd_spacer|small|\nadd_button|yesrfs|`wBack|\nadd_spacer|small|\nadd_button|chc0|Close|\n"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
					}
					if (btn == "yesanc") {

						if (((PlayerInfo*)(peer->data))->gem > 249999)
						{

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "`wSuccessfully `5Purchasing `2Ancestral Items"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;

							((PlayerInfo*)(peer->data))->gem = ((PlayerInfo*)(peer->data))->gem - 250000;
							GamePacket psa = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
							ENetPacket* packetsa = enet_packet_create(psa.data, psa.len, ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packetsa);

							delete psa.data;


							((PlayerInfo*)(peer->data))->boughtAAC = true;

							std::ifstream ifff("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json");


							if (ifff.fail()) {
								ifff.close();


							}
							if (ifff.is_open()) {
							}
							json j;
							ifff >> j; //load


							j["boughtAAC"] = ((PlayerInfo*)(peer->data))->boughtAAC; //edit




							std::ofstream o("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json"); //save
							if (!o.is_open()) {
								cout << GetLastError() << endl;
								_getch();
							}

							o << j << std::endl;


							PlayerInventory inventory;
							InventoryItem item;
							item.itemCount = 1;
							item.itemID = 18;
							inventory.items.push_back(item);
							item.itemCount = 1;
							item.itemID = 32;
							inventory.items.push_back(item);
							item.itemCount = 1;
							item.itemID = 5086;
							inventory.items.push_back(item);
							sendInventory(peer, inventory);


							string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
							BYTE* data = new BYTE[5 + text.length()];
							BYTE zero = 0;
							int type = 3;
							memcpy(data, &type, 4);
							memcpy(data + 4, text.c_str(), text.length()); // change memcpy here
							memcpy(data + 4 + text.length(), &zero, 1); // change memcpy here, revert to 4

							ENetPacket* packetsou = enet_packet_create(data,
								5 + text.length(),
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packetsou);

						}
						else
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`wPayment `4Declined|left|6802|\nadd_spacer|small|\nadd_textbox|`wYour Current Payment has been `4DECLINED `wThis is caused due to Not enough `9Gems`w.|\nadd_spacer|small|\nadd_button|yesanc|`wBack|\nadd_spacer|small|\nadd_button|chc0|Close|\n"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
					}
					if (btn == "refundaac") {
						if (((PlayerInfo*)(peer->data))->gem > 0)
						{

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`2Successfully `wRefunding `5Ancestral items"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;

							((PlayerInfo*)(peer->data))->gem = ((PlayerInfo*)(peer->data))->gem + 125000;
							GamePacket psa = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
							ENetPacket* packetsa = enet_packet_create(psa.data, psa.len, ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packetsa);

							delete psa.data;


							((PlayerInfo*)(peer->data))->boughtAAC = false;

							std::ifstream ifff("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json");


							if (ifff.fail()) {
								ifff.close();


							}
							if (ifff.is_open()) {
							}
							json j;
							ifff >> j; //load


							j["boughtAAC"] = ((PlayerInfo*)(peer->data))->boughtAAC; //edit




							std::ofstream o("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json"); //save
							if (!o.is_open()) {
								cout << GetLastError() << endl;
								_getch();
							}

							o << j << std::endl;


							PlayerInventory inventory;
							InventoryItem item;
							item.itemCount = 1;
							item.itemID = 18;
							inventory.items.push_back(item);
							item.itemCount = 1;
							item.itemID = 32;
							inventory.items.push_back(item);
							item.itemCount = 1;
							item.itemID = 5480;
							inventory.items.push_back(item);
							sendInventory(peer, inventory);


							string text = "action|play_sfx\nfile|audio/success.wav\ndelayMS|0\n";
							BYTE* data = new BYTE[5 + text.length()];
							BYTE zero = 0;
							int type = 3;
							memcpy(data, &type, 4);
							memcpy(data + 4, text.c_str(), text.length()); // change memcpy here
							memcpy(data + 4 + text.length(), &zero, 1); // change memcpy here, revert to 4

							ENetPacket* packetsou = enet_packet_create(data,
								5 + text.length(),
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packetsou);

						}
						else
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Must have 1+ Gems"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
					}
					if (btn == "refunddrt") {
						if (((PlayerInfo*)(peer->data))->gem > 0)
						{

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`2Successfully `wRefunding `5Dr. Tittle"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;

							((PlayerInfo*)(peer->data))->gem = ((PlayerInfo*)(peer->data))->gem + 60000;
							GamePacket psa = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
							ENetPacket* packetsa = enet_packet_create(psa.data, psa.len, ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packetsa);

							delete psa.data;


							((PlayerInfo*)(peer->data))->boughtDRT = false;

							std::ifstream ifff("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json");


							if (ifff.fail()) {
								ifff.close();


							}
							if (ifff.is_open()) {
							}
							json j;
							ifff >> j; //load


							j["boughtDRT"] = ((PlayerInfo*)(peer->data))->boughtDRT; //edit




							std::ofstream o("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json"); //save
							if (!o.is_open()) {
								cout << GetLastError() << endl;
								_getch();
							}

							o << j << std::endl;


							PlayerInventory inventory;
							InventoryItem item;
							item.itemCount = 1;
							item.itemID = 18;
							inventory.items.push_back(item);
							item.itemCount = 1;
							item.itemID = 32;
							inventory.items.push_back(item);
							item.itemCount = 1;
							item.itemID = 5480;
							inventory.items.push_back(item);
							sendInventory(peer, inventory);


							string text = "action|play_sfx\nfile|audio/success.wav\ndelayMS|0\n";
							BYTE* data = new BYTE[5 + text.length()];
							BYTE zero = 0;
							int type = 3;
							memcpy(data, &type, 4);
							memcpy(data + 4, text.c_str(), text.length()); // change memcpy here
							memcpy(data + 4 + text.length(), &zero, 1); // change memcpy here, revert to 4

							ENetPacket* packetsou = enet_packet_create(data,
								5 + text.length(),
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packetsou);

						}
						else
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Must have 1+ Gems"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
					}
					if (btn == "refundfcs") {
						if (((PlayerInfo*)(peer->data))->gem > 0)
						{

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`2Successfully `wRefunding `5Focused Eyes"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;

							((PlayerInfo*)(peer->data))->gem = ((PlayerInfo*)(peer->data))->gem + 40000;
							GamePacket psa = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
							ENetPacket* packetsa = enet_packet_create(psa.data, psa.len, ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packetsa);

							delete psa.data;


							((PlayerInfo*)(peer->data))->boughtFCS = false;

							std::ifstream ifff("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json");


							if (ifff.fail()) {
								ifff.close();


							}
							if (ifff.is_open()) {
							}
							json j;
							ifff >> j; //load


							j["boughtFCS"] = ((PlayerInfo*)(peer->data))->boughtFCS; //edit




							std::ofstream o("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json"); //save
							if (!o.is_open()) {
								cout << GetLastError() << endl;
								_getch();
							}

							o << j << std::endl;


							PlayerInventory inventory;
							InventoryItem item;
							item.itemCount = 1;
							item.itemID = 18;
							inventory.items.push_back(item);
							item.itemCount = 1;
							item.itemID = 32;
							inventory.items.push_back(item);
							item.itemCount = 1;
							item.itemID = 5480;
							inventory.items.push_back(item);
							sendInventory(peer, inventory);


							string text = "action|play_sfx\nfile|audio/success.wav\ndelayMS|0\n";
							BYTE* data = new BYTE[5 + text.length()];
							BYTE zero = 0;
							int type = 3;
							memcpy(data, &type, 4);
							memcpy(data + 4, text.c_str(), text.length()); // change memcpy here
							memcpy(data + 4 + text.length(), &zero, 1); // change memcpy here, revert to 4

							ENetPacket* packetsou = enet_packet_create(data,
								5 + text.length(),
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packetsou);

						}
						else
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Must have 1+ Gems"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
					}
					if (btn == "refunddav") {
						if (((PlayerInfo*)(peer->data))->gem > 0)
						{

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`2Successfully `wRefunding `5Da Vinci Wings"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;

							((PlayerInfo*)(peer->data))->gem = ((PlayerInfo*)(peer->data))->gem + 50000;
							GamePacket psa = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
							ENetPacket* packetsa = enet_packet_create(psa.data, psa.len, ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packetsa);

							delete psa.data;


							((PlayerInfo*)(peer->data))->boughtDAV = false;

							std::ifstream ifff("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json");


							if (ifff.fail()) {
								ifff.close();


							}
							if (ifff.is_open()) {
							}
							json j;
							ifff >> j; //load


							j["boughtDAV"] = ((PlayerInfo*)(peer->data))->boughtDAV; //edit




							std::ofstream o("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json"); //save
							if (!o.is_open()) {
								cout << GetLastError() << endl;
								_getch();
							}

							o << j << std::endl;


							PlayerInventory inventory;
							InventoryItem item;
							item.itemCount = 1;
							item.itemID = 18;
							inventory.items.push_back(item);
							item.itemCount = 1;
							item.itemID = 32;
							inventory.items.push_back(item);
							item.itemCount = 1;
							item.itemID = 5480;
							inventory.items.push_back(item);
							sendInventory(peer, inventory);


							string text = "action|play_sfx\nfile|audio/success.wav\ndelayMS|0\n";
							BYTE* data = new BYTE[5 + text.length()];
							BYTE zero = 0;
							int type = 3;
							memcpy(data, &type, 4);
							memcpy(data + 4, text.c_str(), text.length()); // change memcpy here
							memcpy(data + 4 + text.length(), &zero, 1); // change memcpy here, revert to 4

							ENetPacket* packetsou = enet_packet_create(data,
								5 + text.length(),
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packetsou);

						}
						else
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Must have 1+ Gems"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
					}
					if (btn == "refundgrn") {
						if (((PlayerInfo*)(peer->data))->gem > 0)
						{

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`2Successfully `wRefunding `5Gemini Ring"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;

							((PlayerInfo*)(peer->data))->gem = ((PlayerInfo*)(peer->data))->gem + 4500;
							GamePacket psa = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
							ENetPacket* packetsa = enet_packet_create(psa.data, psa.len, ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packetsa);

							delete psa.data;


							((PlayerInfo*)(peer->data))->boughtGRN = false;

							std::ifstream ifff("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json");


							if (ifff.fail()) {
								ifff.close();


							}
							if (ifff.is_open()) {
							}
							json j;
							ifff >> j; //load


							j["boughtGRN"] = ((PlayerInfo*)(peer->data))->boughtGRN; //edit




							std::ofstream o("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json"); //save
							if (!o.is_open()) {
								cout << GetLastError() << endl;
								_getch();
							}

							o << j << std::endl;


							PlayerInventory inventory;
							InventoryItem item;
							item.itemCount = 1;
							item.itemID = 18;
							inventory.items.push_back(item);
							item.itemCount = 1;
							item.itemID = 32;
							inventory.items.push_back(item);
							item.itemCount = 1;
							item.itemID = 5480;
							inventory.items.push_back(item);
							sendInventory(peer, inventory);


							string text = "action|play_sfx\nfile|audio/success.wav\ndelayMS|0\n";
							BYTE* data = new BYTE[5 + text.length()];
							BYTE zero = 0;
							int type = 3;
							memcpy(data, &type, 4);
							memcpy(data + 4, text.c_str(), text.length()); // change memcpy here
							memcpy(data + 4 + text.length(), &zero, 1); // change memcpy here, revert to 4

							ENetPacket* packetsou = enet_packet_create(data,
								5 + text.length(),
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packetsou);

						}
						else
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Must have 1+ Gems"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
					}
					if (btn == "refundwsd") {
						if (((PlayerInfo*)(peer->data))->gem > 0)
						{

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`2Successfully `wRefunding `5Ring of Winds"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;

							((PlayerInfo*)(peer->data))->gem = ((PlayerInfo*)(peer->data))->gem + 4500;
							GamePacket psa = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
							ENetPacket* packetsa = enet_packet_create(psa.data, psa.len, ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packetsa);

							delete psa.data;


							((PlayerInfo*)(peer->data))->boughtWSD = false;

							std::ifstream ifff("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json");


							if (ifff.fail()) {
								ifff.close();


							}
							if (ifff.is_open()) {
							}
							json j;
							ifff >> j; //load


							j["boughtWSD"] = ((PlayerInfo*)(peer->data))->boughtWSD; //edit




							std::ofstream o("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json"); //save
							if (!o.is_open()) {
								cout << GetLastError() << endl;
								_getch();
							}

							o << j << std::endl;


							PlayerInventory inventory;
							InventoryItem item;
							item.itemCount = 1;
							item.itemID = 18;
							inventory.items.push_back(item);
							item.itemCount = 1;
							item.itemID = 32;
							inventory.items.push_back(item);
							item.itemCount = 1;
							item.itemID = 5480;
							inventory.items.push_back(item);
							sendInventory(peer, inventory);


							string text = "action|play_sfx\nfile|audio/success.wav\ndelayMS|0\n";
							BYTE* data = new BYTE[5 + text.length()];
							BYTE zero = 0;
							int type = 3;
							memcpy(data, &type, 4);
							memcpy(data + 4, text.c_str(), text.length()); // change memcpy here
							memcpy(data + 4 + text.length(), &zero, 1); // change memcpy here, revert to 4

							ENetPacket* packetsou = enet_packet_create(data,
								5 + text.length(),
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packetsou);

						}
						else
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Must have 1+ Gems"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
					}
					if (btn == "refundfrc") {
						if (((PlayerInfo*)(peer->data))->gem > 0)
						{

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`2Successfully `wRefunding `5Ring of Force"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;

							((PlayerInfo*)(peer->data))->gem = ((PlayerInfo*)(peer->data))->gem + 4500;
							GamePacket psa = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
							ENetPacket* packetsa = enet_packet_create(psa.data, psa.len, ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packetsa);

							delete psa.data;


							((PlayerInfo*)(peer->data))->boughtFRC = false;

							std::ifstream ifff("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json");


							if (ifff.fail()) {
								ifff.close();


							}
							if (ifff.is_open()) {
							}
							json j;
							ifff >> j; //load


							j["boughtFRC"] = ((PlayerInfo*)(peer->data))->boughtFRC; //edit




							std::ofstream o("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json"); //save
							if (!o.is_open()) {
								cout << GetLastError() << endl;
								_getch();
							}

							o << j << std::endl;


							PlayerInventory inventory;
							InventoryItem item;
							item.itemCount = 1;
							item.itemID = 18;
							inventory.items.push_back(item);
							item.itemCount = 1;
							item.itemID = 32;
							inventory.items.push_back(item);
							item.itemCount = 1;
							item.itemID = 5480;
							inventory.items.push_back(item);
							sendInventory(peer, inventory);


							string text = "action|play_sfx\nfile|audio/success.wav\ndelayMS|0\n";
							BYTE* data = new BYTE[5 + text.length()];
							BYTE zero = 0;
							int type = 3;
							memcpy(data, &type, 4);
							memcpy(data + 4, text.c_str(), text.length()); // change memcpy here
							memcpy(data + 4 + text.length(), &zero, 1); // change memcpy here, revert to 4

							ENetPacket* packetsou = enet_packet_create(data,
								5 + text.length(),
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packetsou);

						}
						else
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Must have 1+ Gems"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
					}
					if (btn == "refundrfs") {
						if (((PlayerInfo*)(peer->data))->gem > 0)
						{

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`2Successfully `wRefunding `5Rayman's Fists"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;

							((PlayerInfo*)(peer->data))->gem = ((PlayerInfo*)(peer->data))->gem + 15000;
							GamePacket psa = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
							ENetPacket* packetsa = enet_packet_create(psa.data, psa.len, ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packetsa);

							delete psa.data;


							((PlayerInfo*)(peer->data))->boughtRFS = false;

							std::ifstream ifff("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json");


							if (ifff.fail()) {
								ifff.close();


							}
							if (ifff.is_open()) {
							}
							json j;
							ifff >> j; //load


							j["boughtRFS"] = ((PlayerInfo*)(peer->data))->boughtRFS; //edit




							std::ofstream o("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json"); //save
							if (!o.is_open()) {
								cout << GetLastError() << endl;
								_getch();
							}

							o << j << std::endl;


							PlayerInventory inventory;
							InventoryItem item;
							item.itemCount = 1;
							item.itemID = 18;
							inventory.items.push_back(item);
							item.itemCount = 1;
							item.itemID = 32;
							inventory.items.push_back(item);
							item.itemCount = 1;
							item.itemID = 5480;
							inventory.items.push_back(item);
							sendInventory(peer, inventory);


							string text = "action|play_sfx\nfile|audio/success.wav\ndelayMS|0\n";
							BYTE* data = new BYTE[5 + text.length()];
							BYTE zero = 0;
							int type = 3;
							memcpy(data, &type, 4);
							memcpy(data + 4, text.c_str(), text.length()); // change memcpy here
							memcpy(data + 4 + text.length(), &zero, 1); // change memcpy here, revert to 4

							ENetPacket* packetsou = enet_packet_create(data,
								5 + text.length(),
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packetsou);

						}
						else
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Must have 1+ Gems"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
					}
					if (btn == "refundfye") {
						if (((PlayerInfo*)(peer->data))->gem > 0)
						{

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`2Successfully `wRefunding `5War Hammer of Darnkess"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;

							((PlayerInfo*)(peer->data))->gem = ((PlayerInfo*)(peer->data))->gem + 2500000;
							GamePacket psa = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
							ENetPacket* packetsa = enet_packet_create(psa.data, psa.len, ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packetsa);

							delete psa.data;


							((PlayerInfo*)(peer->data))->boughtFYE = false;

							std::ifstream ifff("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json");


							if (ifff.fail()) {
								ifff.close();


							}
							if (ifff.is_open()) {
							}
							json j;
							ifff >> j; //load


							j["boughtFYE"] = ((PlayerInfo*)(peer->data))->boughtFYE; //edit




							std::ofstream o("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json"); //save
							if (!o.is_open()) {
								cout << GetLastError() << endl;
								_getch();
							}

							o << j << std::endl;


							PlayerInventory inventory;
							InventoryItem item;
							item.itemCount = 1;
							item.itemID = 18;
							inventory.items.push_back(item);
							item.itemCount = 1;
							item.itemID = 32;
							inventory.items.push_back(item);
							item.itemCount = 1;
							item.itemID = 5480;
							inventory.items.push_back(item);
							sendInventory(peer, inventory);


							string text = "action|play_sfx\nfile|audio/success.wav\ndelayMS|0\n";
							BYTE* data = new BYTE[5 + text.length()];
							BYTE zero = 0;
							int type = 3;
							memcpy(data, &type, 4);
							memcpy(data + 4, text.c_str(), text.length()); // change memcpy here
							memcpy(data + 4 + text.length(), &zero, 1); // change memcpy here, revert to 4

							ENetPacket* packetsou = enet_packet_create(data,
								5 + text.length(),
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packetsou);

						}
						else
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Must have 1+ Gems"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
					}
#endif
				}
				if (cch.find("text|") != std::string::npos){
					PlayerInfo* pData = ((PlayerInfo*)(peer->data));
					if (str == "/ghost")
					{
						((PlayerInfo*)(peer->data))->skinColor = -150;
						sendClothes(peer);
						cout << "/ghost from " << ((PlayerInfo*)(peer->data))->displayName << endl;
						((PlayerInfo*)(peer->data))->canWalkInBlocks = true;
						sendState(peer);
						/*PlayerMoving data;
						data.packetType = 0x14;
						data.characterState = 0x0; // animation
						data.x = 1000;
						data.y = 1;
						data.punchX = 0;
						data.punchY = 0;
						data.XSpeed = 300;
						data.YSpeed = 600;
						data.netID = ((PlayerInfo*)(peer->data))->netID;
						data.plantingTree = 0xFF;
						SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);*/
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oYour atoms starts shivering and you felt a flow through your spine (ghost mod added)``"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						string text = "action|play_sfx\nfile|audio/secret.wav\ndelayMS|0\n";
						BYTE* data = new BYTE[5 + text.length()];
						BYTE zero = 0;
						int type = 3;
						memcpy(data, &type, 4);
						memcpy(data + 4, text.c_str(), text.length());
						memcpy(data + 4 + text.length(), &zero, 1);
						ENetPacket* packet2 = enet_packet_create(data,
							5 + text.length(),
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet2);
						delete p.data;
						delete data;
					}
					else if (str.substr(0, 7) == "/state ")
					{
						PlayerMoving data;
						data.packetType = 0x14;
						data.characterState = 0x0; // animation
						data.x = 1000;
						data.y = 0;
						data.punchX = 0;
						data.punchY = 0;
						data.XSpeed = 300;
						data.YSpeed = 600;
						data.netID = ((PlayerInfo*)(peer->data))->netID;
						data.plantingTree = atoi(str.substr(7, cch.length() - 7 - 1).c_str());
						SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
					}
					else if (str == "/unequip")
					{
						((PlayerInfo*)(peer->data))->cloth_hair = 0;
						((PlayerInfo*)(peer->data))->cloth_shirt = 0;
						((PlayerInfo*)(peer->data))->cloth_pants = 0;
						((PlayerInfo*)(peer->data))->cloth_feet = 0;
						((PlayerInfo*)(peer->data))->cloth_face = 0;
						((PlayerInfo*)(peer->data))->cloth_hand = 0;
						((PlayerInfo*)(peer->data))->cloth_back = 0;
						((PlayerInfo*)(peer->data))->cloth_mask = 0;
						((PlayerInfo*)(peer->data))->cloth_necklace = 0;
						((PlayerInfo*)(peer->data))->cloth_ances = 0;
						sendClothes(peer);
					}
					else if (str == "/rules") {
						GamePacket news = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wHelp & Rules|left|6128|\nadd_spacer|small|\nadd_label|small|`wTo keep this Community safe we've got some ground rules to check out:|left|\nadd_spacer|small|\nadd_label_with_icon|small|`wKeep your `4Password `wSecret. Sharing your `4Password `wWill result in stolen Data.|left|1432|\nadd_label_with_icon|small|`wBe civil. Bullying, Racism,excessive profanity, sexual content, and abusive behaviour are not allowed.|left|1432|\nadd_label_with_icon|small|`wPlayers that harmful the community may be banned. This includes accounts that use lies, fake games, or trickery to mistreat other players.|left|1432|\nadd_label_with_icon|small|`wTrying to ask for punishment will just lead into a worse punishment.|left|1432|\nadd_label_with_icon|small|`wIf you find a world or player that is violating our rules, message a `#@Moderator`w.|left|1432|\nadd_label_with_icon|small|`wSelling gems/account for outside server items is `5ILLEGAL`w, if you found a player performing this action please message a `#@Moderator`w.|left|1432|\nadd_label_with_icon|small|`wDo not Broadcast rude stuffs|left|1432|\nadd_label_with_icon|small|`wDo Not War Broadcasting|left|1432|\nadd_label_with_icon|small|`#@Moderators `where are to enforce the rules. Abusing, Spamming, or harrasing moderators will have consequences|left|1432|\nadd_label_with_icon|small|`wYour worlds could be deleted at any time. We do everything in our power to prevent this, but worlds cannot be restored.|left|1432|\nadd_label_with_icon|small|`wDon't Copy others Identity!|left|1432|\nadd_label_with_icon|small|`wDon't Impersonating People Name. [For `1VIP `wor Above].|left|1432|\nadd_spacer|small|\nadd_label|small|`wThank You!|left|\nadd_spacer|small|\nadd_label|small|`w~ `6@Valkrie#1234 `w& `6@Luc1Fer#1337 ``|left|\nadd_spacer|small|\nadd_smalltext|`4NOTE: `wBy clicking the button '`9I Accept the Rules`w' You will never ever break the rules above.|\nadd_spacer|small|\nadd_button|chc0|`9I Accept the Rules!|\n"));
						ENetPacket* packet = enet_packet_create(news.data,
							news.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						
						//enet_host_flush(server);
						delete news.data;
					}
					else if (str == "/purchase") {
						GamePacket news = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`wWelcome to our shop!|left|1430|\nadd_spacer|small|\nadd_textbox|`rPlease choose item that you want to purchase!|\nadd_spacer|small|\nadd_label_with_icon|small|`6Special Items`4:|left|7912|\nset_labelXMult|1.2\nadd_button_with_icon|aac||staticBlueFrame|5078|250000|\nadd_button_with_icon|fye||staticBlueFrame|7912|5000000|\nadd_button_with_icon|rfs||staticBlueFrame|5480|50000|\nadd_button_with_icon||END_LIST|noflags|0|0|\nadd_spacer|small|\nadd_label_with_icon|small|`6Rare Items`4:|left|8286|\nset_labelXMult|1.2\nadd_button_with_icon|fcs||staticBlueFrame|1204|10000|\nadd_button_with_icon|dav||staticBlueFrame|8286|100000|\nadd_button_with_icon||END_LIST|noflags|0|0|\nadd_spacer|small|\nadd_label_with_icon|small|`6Carnival Items`4:|left|1900|\nset_labelXMult|1.2\nadd_button_with_icon|wsd||staticBlueFrame|1876|7500|\nadd_button_with_icon|frc||staticBlueFrame|1874|7500|\nadd_button_with_icon|grn||staticBlueFrame|1986|7500|\nadd_button_with_icon||END_LIST|noflags|0|0|\nadd_spacer|small|\nadd_label_with_icon|small|`6Title Items`4:|left|3130|\nset_labelXMult|1.2\nadd_button_with_icon|drt||staticBlueFrame|3130|125000|\nadd_button_with_icon||END_LIST|noflags|0|0|\nadd_spacer|small|\nadd_button|chc0|`wBack|\n"));
						ENetPacket* packet = enet_packet_create(news.data,
							news.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);

						//enet_host_flush(server);
						delete news.data;
					}
					else if (str == "/news") {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wGrowtopiaFX``|left|2252|\n\nadd_spacer|small|\nadd_label_with_icon|small|\nadd_button|crash|`w[`4Fix Crash`w] `eRemove Clothes|noflags|0|0|\n\nadd_image_button|banner|interface/large/anni_sta.rttex|noflags|||\nadd_textbox|`wDecember 26: `5GTFX Update!|left|6746|\nadd_spacer|small|\nadd_textbox|`wDear GrowtopiaFX Players:|\nadd_textbox|`9Christmas is unfortanetly over! We would love to wish you all a happy new year!|\nadd_spacer|small|\nadd_textbox|`w- The GrowtopiaFX Team|\nadd_spacer|small|\nadd_url_button||`9Join our Discord``|NOFLAGS|https://discord.gg/HhGsqws|Open link?|0|0| |left|6746|\nadd_spacer|small|\nadd_label_with_icon|small|`4WARNING:`` `5Worlds And Accounts might be deleted at any time if database issues appear (once per day or week).|left|1432|\nadd_label_with_icon|small|`4WARNING:`` `5Accounts`` are in beta, bugs may appear and they will be probably deleted often, because of new accounts updates, which will cause database incompatibility.|left|1432|\nadd_spacer|small|\nadd_textbox|`4WARNING: `wDon't Forget to Follow the `4/Rules`w.|\nadd_spacer|small|\nadd_button|closenews|`9Continue|"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet); 


						//enet_host_flush(server);
						delete p.data;
					}
					else if (str.substr(0, 6) == "/reset") {
						if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
						cout << "Restart from " << ((PlayerInfo*)(peer->data))->displayName << endl;
						GamePacket p = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/science_button.rttex"), "Restarting soon!"), "audio/mp3/suspended.mp3"), 0));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						ENetPeer* currentPeer;
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							enet_peer_send(currentPeer, 0, packet);
						}
						delete p.data;
						//enet_host_flush(server);
					}
					else if (str == "/find")
					{
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`wItem Finder``|left|6016|\nadd_textbox|Enter a word to find the item|\nadd_text_input|item|Item Name||30|\nend_dialog|findid|Cancel|Find the item!|\nadd_quick_exit|\n"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);

						//enet_host_flush(server);
						delete p.data;
					}

					else if (str.substr(0, 5) == "/pay ") {
						using namespace std::chrono;

						string lvl_info = str;

						size_t extra_space = lvl_info.find("  ");
						if (extra_space != std::string::npos) {
							lvl_info.replace(extra_space, 2, " ");
						}

						string delimiter = " ";
						size_t pos = 0;
						string lvl_user;
						string lvl_amount;
						if ((pos = lvl_info.find(delimiter)) != std::string::npos) {
							lvl_info.erase(0, pos + delimiter.length());
						}
						else {
							GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6>> Please specify a Player you'd like to send Gems to!"));
							ENetPacket* packet = enet_packet_create(ps.data,
								ps.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete ps.data;
						}

						if ((pos = lvl_info.find(delimiter)) != std::string::npos) {
							lvl_user = lvl_info.substr(0, pos);
							lvl_info.erase(0, pos + delimiter.length());
						}
						else {
							GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6>> Please enter your desired ammount of Gems that you'd like to Send to player!"));
							ENetPacket* packet = enet_packet_create(ps.data,
								ps.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete ps.data;
						}
						lvl_amount = lvl_info;
						if (lvl_amount == "") {
							GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6>> Please enter the Ammount of Gems that you'd like to Send to player!"));
							ENetPacket* packet = enet_packet_create(ps.data,
								ps.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete ps.data;
							continue;
						}
						if (lvl_amount.length() > 9) {
							GamePacket p0 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6>> Too Short of That Gem Ammount!"));
							ENetPacket* packet0 = enet_packet_create(p0.data,
								p0.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet0);
							delete p0.data;
							continue;
						}
						int x;

						try {
							x = stoi(lvl_amount);
						}
						catch (std::invalid_argument& e) {
							GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6>> Please Only include Numbers!"));
							ENetPacket* packet = enet_packet_create(ps.data,
								ps.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete ps.data;
							continue;
						}
						if (lvl_amount.find(" ") != string::npos || lvl_amount.find(".") != string::npos || lvl_amount.find(",") != string::npos || lvl_amount.find("@") != string::npos || lvl_amount.find("[") != string::npos || lvl_amount.find("]") != string::npos || lvl_amount.find("#") != string::npos || lvl_amount.find("<") != string::npos || lvl_amount.find(">") != string::npos || lvl_amount.find(":") != string::npos || lvl_amount.find("{") != string::npos || lvl_amount.find("}") != string::npos || lvl_amount.find("|") != string::npos || lvl_amount.find("+") != string::npos || lvl_amount.find("_") != string::npos || lvl_amount.find("~") != string::npos || lvl_amount.find("-") != string::npos || lvl_amount.find("!") != string::npos || lvl_amount.find("$") != string::npos || lvl_amount.find("%") != string::npos || lvl_amount.find("^") != string::npos || lvl_amount.find("&") != string::npos || lvl_amount.find("`") != string::npos || lvl_amount.find("*") != string::npos || lvl_amount.find("(") != string::npos || lvl_amount.find(")") != string::npos || lvl_amount.find("=") != string::npos || lvl_amount.find("'") != string::npos || lvl_amount.find(";") != string::npos || lvl_amount.find("/") != string::npos) {
							GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6>> Do not Include `wSpecial Characters `6in Your Gem Ammount!"));
							ENetPacket* packet = enet_packet_create(ps.data,
								ps.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete ps.data;
							continue;
						}
						ENetPeer* currentPeer;

						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;

							if (((PlayerInfo*)(currentPeer->data))->rawName == PlayerDB::getProperName(lvl_user)) {
								if (stoi(lvl_amount) <= 0) {
									GamePacket p8 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6That Gem ammount is Too Short!"));
									ENetPacket* packet8 = enet_packet_create(p8.data,
										p8.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet8);
									delete p8.data;
									continue;
								}
								if (((PlayerInfo*)(peer->data))->gem < stoi(lvl_amount)) {
									GamePacket p8 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6>> You do Not Have Enough Gems to send to That Player, You Must have a Value of 1Or Greater!"));
									ENetPacket* packet8 = enet_packet_create(p8.data,
										p8.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet8);
									delete p8.data;
									continue;
								}
								if (((PlayerInfo*)(currentPeer->data))->rawName == ((PlayerInfo*)(peer->data))->rawName) {
									GamePacket p0 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6>> You can't Pay yourself!"));
									ENetPacket* packet0 = enet_packet_create(p0.data,
										p0.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet0);
									delete p0.data;
									continue;
								}
								string gem = std::to_string(((PlayerInfo*)(currentPeer->data))->gem + stoi(lvl_amount));
								if (gem.length() > 9) {
									GamePacket p0 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6>> That player already has too Many Gems!"));
									ENetPacket* packet0 = enet_packet_create(p0.data,
										p0.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet0);
									delete p0.data;
									continue;
								}

								((PlayerInfo*)(peer->data))->gem = ((PlayerInfo*)(peer->data))->gem - stoi(lvl_amount);
								((PlayerInfo*)(currentPeer->data))->gem = ((PlayerInfo*)(currentPeer->data))->gem + stoi(lvl_amount);

								GamePacket p67 = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
								ENetPacket* packet67 = enet_packet_create(p67.data,
									p67.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet67);
								delete p67.data;
								GamePacket p0 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6>> You have paid: `2" + ((PlayerInfo*)(currentPeer->data))->displayName + "`6With Gem ammount: `2" + lvl_amount + "`6!"));
								ENetPacket* packet0 = enet_packet_create(p0.data,
									p0.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet0);
								delete p0.data;
								GamePacket p68 = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(currentPeer->data))->gem));
								ENetPacket* packet68 = enet_packet_create(p68.data,
									p68.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(currentPeer, 0, packet68);
								delete p68.data;
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`6>> Player: `2" + ((PlayerInfo*)(peer->data))->displayName + " `6have paid you `2" + lvl_amount + "`6 Gems!"));
								string text = "action|play_sfx\nfile|audio/piano_nice.wav\ndelayMS|0\n";
								BYTE* data = new BYTE[5 + text.length()];
								BYTE zero = 0;
								int type = 3;
								memcpy(data, &type, 4);
								memcpy(data + 4, text.c_str(), text.length());
								memcpy(data + 4 + text.length(), &zero, 1);
								ENetPacket* packet2 = enet_packet_create(data,
									5 + text.length(),
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(currentPeer, 0, packet2);
								delete data;

								ENetPacket* packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packet);
								delete ps.data;
								break;
							}
						}
					}
					else if (str.substr(0, 6) == "/give ")
					{
						if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
						((PlayerInfo*)(peer->data))->gem = atoi(str.substr(6).c_str());
						GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet);
						delete p.data;
						continue;

						// thank to iProgramInCpp#0489       


					}
					else if (str.substr(0, 8) == "/summon ") {
						if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) > 0) {
							string name = str.substr(8, str.length());


							ENetPeer* currentPeer;


							bool found = false;


							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;


								string name2 = ((PlayerInfo*)(currentPeer->data))->rawName;


								std::transform(name.begin(), name.end(), name.begin(), ::tolower);
								std::transform(name2.begin(), name2.end(), name2.begin(), ::tolower);


								if (name == name2) {
									sendPlayerToPlayer(currentPeer, peer);
									found = true;
								}


							}
							if (found) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`9Summoning " + name));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
							}
							else {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Player not found!"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
							}
						}


					}
					else if (str == "/nuke") {
						if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) > 0) {
							cout << "nuke from " << ((PlayerInfo*)(peer->data))->rawName << " in world " << ((PlayerInfo*)(peer->data))->currentWorld << "with IP " << std::hex << peer->address.host << std::dec << " with message " << str.substr(5, cch.length() - 5 - 1) << endl;
							WorldInfo* world = getPlyersWorld(peer);
							if (world->nuked) {
								world->nuked = false;
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`2You have un-nuked the world"));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
							}
							else {
								world->nuked = true;
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4You have nuked the world!"));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);

								ENetPeer* currentPeer;

								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;

									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`$>>`4" + world->name + " was nuked from orbit.`$ it's the only way to be sure, play nice everybody!"));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									string text = "action|play_sfx\nfile|audio/bigboom.wav\ndelayMS|0\n";
									BYTE* data = new BYTE[5 + text.length()];
									BYTE zero = 0;
									int type = 3;
									memcpy(data, &type, 4);
									memcpy(data + 4, text.c_str(), text.length());
									memcpy(data + 4 + text.length(), &zero, 1);


									ENetPacket* packetnuk = enet_packet_create(data,
										5 + text.length(),
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packetnuk);
									delete data;
									delete p.data;
								}
							}
						}
					}
					else if (str.substr(0, 7) == "/unban ") {
						if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
						std::ifstream ifff("players/" + PlayerDB::getProperName(str.substr(7, cch.length() - 7 - 1)) + ".json");
						if (ifff.fail()) {
							ifff.close();
							continue;
						}
						if (ifff.is_open()) {
						}
						json j;
						ifff >> j; //load


						j["banned"] = false; //edit

						std::ofstream o("players/" + PlayerDB::getProperName(str.substr(7, cch.length() - 7 - 1)) + ".json"); //save
						if (!o.is_open()) {
							cout << GetLastError() << endl;
							_getch();
						}

						o << j << std::endl;
					}
					else if (str.substr(0, 6) == "/findp ") {
						if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
						if (str.substr(6, cch.length() - 6 - 1) == "") continue;

						ENetPeer* currentPeer;

						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Finding user: " + str.substr(6, cch.length() - 6 - 1)));

						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;

					for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
					{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
							continue;

						if (((PlayerInfo*)(currentPeer->data))->rawName == str.substr(6, cch.length() - 6 - 1)) {
								if (((PlayerInfo*)(currentPeer->data))->haveGrowId == false) continue;
								GamePacket psp = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Found  " + str.substr(6, cch.length() - 6 - 1) + " at: " + ((PlayerInfo*)(currentPeer->data))->currentWorld));

								ENetPacket* packetd = enet_packet_create(psp.data,
									psp.len,
									ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packetd);
							delete psp.data;
						 }
					}
				}
					else if (str.substr(0, 5) == "/pe ") {
						GamePacket psp = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), atoi(str.substr(5).c_str())));

					ENetPacket * packetd = enet_packet_create(psp.data,
							psp.len,
							ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packetd);
				    delete psp.data;
						}
					else if (str.substr(0, 6) == "/txts ") {
				    GamePacket psp = packetEnd(appendString(appendString(createPacket(), "OnSDBroadcast"), str.substr(6, cch.length() - 6 - 1) + "!"));

					ENetPacket* packetd = enet_packet_create(psp.data,
						 psp.len,
						 ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packetd);
					delete psp.data;
						}
					else if (str == "/mods") {
						string x;

						ENetPeer* currentPeer;

						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;

							if (isMod(((PlayerInfo*)(currentPeer->data))->rawName, ((PlayerInfo*)(currentPeer->data))->tankIDPass) > 0) {
								x.append("`^" + ((PlayerInfo*)(currentPeer->data))->rawName + "``, ");
							}

						}
						x = x.substr(0, x.length() - 2);

						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`o>> `5Moderators online`o: " + x));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
					}

					else if (str == "/vips") {
					string x;

					ENetPeer* currentPeer;

					for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
					{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
							continue;

						if (isVIP(((PlayerInfo*)(currentPeer->data))->rawName, ((PlayerInfo*)(currentPeer->data))->tankIDPass) > 0) {
							x.append("`1" + ((PlayerInfo*)(currentPeer->data))->rawName + "``, ");
						}

					}
					x = x.substr(0, x.length() - 2);

					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`o>> `5VIPs online`o: " + x));
					ENetPacket* packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);
					}
					else if (str.substr(0, 6) == "/nick ") {
					if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;
					ENetPeer* currentPeer;

					for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
					{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
							continue;
						if (isHere(peer, currentPeer))
						{
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnNameChanged"), "``"+ str.substr(6, cch.length() - 6 - 1)));
							((PlayerInfo*)(peer->data))->displayName = str.substr(6, cch.length() - 6 - 1);
							memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
							ENetPacket* packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(currentPeer, 0, packet2);
							delete p2.data;
						}
					}
						}
					else if (str.substr(0, 6) == "/mute ")
						{
						if (!isMod(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
						ENetPeer* currentPeer;
						string dupa;
						string pa;
						string imie = str.substr(6, cch.length() - 6 - 1);
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							if (((PlayerInfo*)(currentPeer->data))->rawName == imie or ((PlayerInfo*)(currentPeer->data))->displayName == imie)
							{
								((PlayerInfo*)(currentPeer->data))->taped = true;
								dupa = ((PlayerInfo*)(currentPeer->data))->rawName;
								pa = ((PlayerInfo*)(currentPeer->data))->displayName;
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You got `4Muted`o by `4ADMIN`o!"));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packet);
								delete p.data;
								((PlayerInfo*)(currentPeer->data))->cloth_face = 408;
								sendClothes(currentPeer);
							}
						}
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`#**`w" + ((PlayerInfo*)(peer->data))->rawName + "`o has `4Muted`o player`w " + imie + "`#**"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							enet_peer_send(currentPeer, 0, packet);
						}
						delete p.data;
						continue;
						}
					else if (str.substr(0, 8) == "/kickall") {

						if (world->name != "ADMIN") {
							if (world->owner != "") {
								if (((PlayerInfo*)(peer->data))->rawName == world->owner || isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass))

								{
									ENetPeer* currentPeer;

									for (currentPeer = server->peers;
										currentPeer < &server->peers[server->peerCount];
										++currentPeer)
									{
										if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
											continue;
										if (isHere(peer, currentPeer))
										{
											sendPlayerLeave(currentPeer, (PlayerInfo*)(event.peer->data));
											((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
											sendWorldOffers(currentPeer);



											GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "All kicked out the world!"));
											ENetPacket* packet = enet_packet_create(ps.data,
												ps.len,
												ENET_PACKET_FLAG_RELIABLE);

											enet_peer_send(peer, 0, packet);
											delete ps.data;
										}
									}
								}
							}
						}
					}
					else if (str == "/help"){
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`o>> `5Supported Commands are`o: /help, /?, /news, /rules, /mods, /vips, /item <id>, /find, /online, /ghost, /unghost, /pay <player> <amount>, /howgay, /nocasino (disable /ghost in world), /casino (enable /ghost), /pull, /kick, /wban, /sb, /ssb (must own war hammer), /weather <id>, /time, /giveworld <player name>, /bluename (disable BlueName for Level 125+), /unequip, /specials, /radio, /vhelp (must purchase vip), /ahelp (must purchase mini-mod+), /ohelp (sc only), /wl, /gc <text>, /purchase, /save, /kickall, /color <id>"));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
						//enet_host_flush(server);
					}
					else if (str == "/?/") {
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`o>> `2Player Commands are`o: /help, /?, /news, /rules, /mods, /vips, /item <id>, /find, /online, /ghost, /unghost, /pay <player> <amount>, /howgay, /nocasino (disable /ghost in world), /casino (enable /ghost), /pull, /kick, /wban, /sb, /ssb (must own war hammer), /weather <id>, /time, /giveworld <player name>, /bluename (disable BlueName for Level 125+), /unequip, /specials, /radio, /vhelp (must purchase vip), /ahelp (must purchase mini-mod+), /ohelp (sc only), /wl, /gc <text>, /purchase, /save, /kickall, /color <id>"));
					ENetPacket* packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);
					delete p.data;
					//enet_host_flush(server);
					}
					else if (str == "/removetext") {
						{
							string username1;
							string real = "";
							string imie = ((PlayerInfo*)(peer->data))->rawName;


							((PlayerInfo*)(peer->data))->boughtMEM = false;

							std::ifstream ifff("players/" + imie + ".json");


							if (ifff.fail()) {
								ifff.close();


							}
							if (ifff.is_open()) {
							}
							json j;
							ifff >> j; //load


							j["boughtMEM"] = ((PlayerInfo*)(peer->data))->boughtMEM; //edit

							std::ofstream o("players/" + imie + ".json"); //save
							if (!o.is_open()) {
								_getch();
							}
							o << j << std::endl;
						}
							}
					else if (str == "/claimchat") {
						{
							string username1;
							string real = "";
							string imie = ((PlayerInfo*)(peer->data))->rawName;


							((PlayerInfo*)(peer->data))->boughtMEM = true;

							std::ifstream ifff("players/" + imie + ".json");


							if (ifff.fail()) {
								ifff.close();


							}
							if (ifff.is_open()) {
							}
							json j;
							ifff >> j; //load


							j["boughtMEM"] = ((PlayerInfo*)(peer->data))->boughtMEM; //edit

							std::ofstream o("players/" + imie + ".json"); //save
							if (!o.is_open()) {
								_getch();
							}
							o << j << std::endl;
						}
							}
					else if (str.substr(0, 16) == "/ban ") {
						if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue; {
							string name = str.substr(16, str.length());
							ENetPeer* currentPeer;

							bool found = false;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;

								if (((PlayerInfo*)(currentPeer->data))->rawName == name) {
									found = true;
									if (((PlayerInfo*)(currentPeer->data))->haveGrowId) {

										PlayerInfo* p = ((PlayerInfo*)(currentPeer->data));
										p->ban = 1;
										string username = PlayerDB::getProperName(p->rawName);

										std::ofstream o("players/" + username + ".json");
										if (!o.is_open()) {
											cout << GetLastError() << endl;
											_getch();
										}
										json j;
										int clothback = p->cloth_back;
										int clothhand = p->cloth_hand;
										int clothface = p->cloth_face;
										int clothhair = p->cloth_hair;
										int clothfeet = p->cloth_feet;
										int clothpants = p->cloth_pants;
										int clothneck = p->cloth_necklace;
										int clothshirt = p->cloth_shirt;
										int clothmask = p->cloth_mask;
										int clothances = p->cloth_ances;
										int skin = p->skinColor;
										int ban = p->ban;

										string password = ((PlayerInfo*)(currentPeer->data))->tankIDPass;
										j["username"] = username;
										j["password"] = hashPassword(password);
										j["adminlevel"] = 999;
										j["ClothBack"] = clothback;
										j["ClothHand"] = clothhand;
										j["ClothFace"] = clothface;
										j["ClothShirt"] = clothshirt;
										j["ClothPants"] = clothpants;
										j["ClothNeck"] = clothneck;
										j["ClothHair"] = clothhair;
										j["ClothFeet"] = clothfeet;
										j["ClothMask"] = clothmask;
										j["ClothAnces"] = clothances;
										j["Skin"] = skin;
										j["banned"] = true;
										j["boughtMEM"] = ((PlayerInfo*)(currentPeer->data))->boughtMEM;
										j["boughtFYE"] = ((PlayerInfo*)(currentPeer->data))->boughtFYE;
										j["boughtAAC"] = ((PlayerInfo*)(currentPeer->data))->boughtAAC;
										j["boughtRFS"] = ((PlayerInfo*)(currentPeer->data))->boughtRFS;
										j["boughtWSD"] = ((PlayerInfo*)(currentPeer->data))->boughtWSD;
										j["boughtGRN"] = ((PlayerInfo*)(currentPeer->data))->boughtGRN;
										j["boughtFRC"] = ((PlayerInfo*)(currentPeer->data))->boughtFRC;
										j["boughtFCS"] = ((PlayerInfo*)(currentPeer->data))->boughtFCS;
										j["boughtDAV"] = ((PlayerInfo*)(currentPeer->data))->boughtDAV;
										j["boughtDRT"] = ((PlayerInfo*)(currentPeer->data))->boughtDRT;
										o << j << std::endl;
									}
									enet_peer_disconnect_later(peer, 0);
								}
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`2You are now a Super-Admin!"));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packet);
								delete p.data;
								{
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`2" + name + "`9has recieved Super-Admin."));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);

									if (!found) {
										GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Player not found!"));
										ENetPacket* packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet);
									}
									else {
										GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4You need to have a higher admin-level to do that!"));
										ENetPacket* packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet);
									}
								}
							}
						}
					}
					else if (str.substr(0, 10) == "/givevips ") {
					if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue; {
						string name = str.substr(10, str.length());
						ENetPeer* currentPeer;

						bool found = false;

						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;

							if (((PlayerInfo*)(currentPeer->data))->rawName == name) {
								found = true;
								if (((PlayerInfo*)(currentPeer->data))->haveGrowId) {

									PlayerInfo* p = ((PlayerInfo*)(currentPeer->data));
									p->ban = 1;
									string username = PlayerDB::getProperName(p->rawName);

									std::ofstream o("players/" + username + ".json");
									if (!o.is_open()) {
										cout << GetLastError() << endl;
										_getch();
									}
									json j;
									int clothback = p->cloth_back;
									int clothhand = p->cloth_hand;
									int clothface = p->cloth_face;
									int clothhair = p->cloth_hair;
									int clothfeet = p->cloth_feet;
									int clothpants = p->cloth_pants;
									int clothneck = p->cloth_necklace;
									int clothshirt = p->cloth_shirt;
									int clothmask = p->cloth_mask;
									int clothances = p->cloth_ances;
									int skin = p->skinColor;
									int ban = p->ban;

									string password = ((PlayerInfo*)(currentPeer->data))->tankIDPass;
									j["username"] = username;
									j["password"] = hashPassword(password);
									j["adminlevel"] = 333;
									j["ClothBack"] = clothback;
									j["ClothHand"] = clothhand;
									j["ClothFace"] = clothface;
									j["ClothShirt"] = clothshirt;
									j["ClothPants"] = clothpants;
									j["ClothNeck"] = clothneck;
									j["ClothHair"] = clothhair;
									j["ClothFeet"] = clothfeet;
									j["ClothMask"] = clothmask;
									j["ClothMask"] = clothances;
									j["Skin"] = skin;
									j["banned"] = true;
									j["boughtMEM"] = ((PlayerInfo*)(currentPeer->data))->boughtMEM;
									j["boughtFYE"] = ((PlayerInfo*)(currentPeer->data))->boughtFYE;
									j["boughtAAC"] = ((PlayerInfo*)(currentPeer->data))->boughtAAC;
									j["boughtRFS"] = ((PlayerInfo*)(currentPeer->data))->boughtRFS;
									j["boughtWSD"] = ((PlayerInfo*)(currentPeer->data))->boughtWSD;
									j["boughtGRN"] = ((PlayerInfo*)(currentPeer->data))->boughtGRN;
									j["boughtFRC"] = ((PlayerInfo*)(currentPeer->data))->boughtFRC;
									j["boughtFCS"] = ((PlayerInfo*)(currentPeer->data))->boughtFCS;
									j["boughtDAV"] = ((PlayerInfo*)(currentPeer->data))->boughtDAV;
									j["boughtDRT"] = ((PlayerInfo*)(currentPeer->data))->boughtDRT;

									o << j << std::endl;
								}
								enet_peer_disconnect_later(peer, 0);
							}
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`2You are now a VIP!"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(currentPeer, 0, packet);
							delete p.data;
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`2" + name + "`9has recieved VIP."));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);

								if (!found) {
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Player not found!"));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
								}
								else {
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4You need to have a higher admin-level to do that!"));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
								}
							}
						}
					}
					}
					else if (str == "/ahelp") {
					if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`o>> `4Administrator commands are`o: /ban <player name>, /unban (to unban player account), / <your text> (mod chat), /warn <player name> <text> (warn player), /mute <player>, /hide (hide your status from /mods), /ghosts (same as `#/ghost `oeven if world disabled no clip), /summon <player> (For Admin), /warpto <player>, /drop <id>, /take, /nuke, /unnuke, /checkban <player>, /checkip <player> (Showing Player Address Host), /freeze <player>, /unfreeze <player>, /curse <player>, /uncurse <player>, /asb <text>, /sw (Save All Worlds), /cn <player> <new nickname>, /pl, /gsm <text>"));
					ENetPacket* packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);
					delete p.data;
					//enet_host_flush(server);
					}
						else if (str.substr(0, 5) == "/null_gem ") //gem if u want flex with ur gems!
						{
						GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), atoi(str.substr(5).c_str())));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet);
						delete p.data;
						continue;


						}
					else if (str.substr(0, 9) == "/weather ") {
							if (world->name != "ADMIN") {
								if (world->owner != "") {
									if (((PlayerInfo*)(peer->data))->rawName == world->owner || isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass))

									{
										ENetPeer* currentPeer;

										for (currentPeer = server->peers;
											currentPeer < &server->peers[server->peerCount];
											++currentPeer)
										{
											if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
												continue;
											if (isHere(peer, currentPeer))
											{
												GamePacket p1 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oPlayer `2" + ((PlayerInfo*)(peer->data))->displayName + "`o has just changed the world's weather!"));
												ENetPacket * packet1 = enet_packet_create(p1.data,
													p1.len,
													ENET_PACKET_FLAG_RELIABLE);

												enet_peer_send(currentPeer, 0, packet1);
												delete p1.data;

												GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), atoi(str.substr(9).c_str())));
												ENetPacket * packet2 = enet_packet_create(p2.data,
													p2.len,
													ENET_PACKET_FLAG_RELIABLE);

												enet_peer_send(currentPeer, 0, packet2);
												delete p2.data;
												continue; /*CODE UPDATE /WEATHER FOR EVERYONE!*/
											}
										}
									}
								}
							}
						}
					else if (str == "/online") {

					string online = "";
					int total = 0;
					ENetPeer* currentPeer;

					for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
					{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
							continue;
						if (getAdminLevel(((PlayerInfo*)(currentPeer->data))->rawName, ((PlayerInfo*)(currentPeer->data))->tankIDPass) >= 0) {
							online += ((PlayerInfo*)(currentPeer->data))->displayName + "`o, `w";
							total++;
						}
					}
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`5Players online [`wTotal: `2" + to_string(total) + "`5]: `w" + online));
					ENetPacket* packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);
					delete p.data;
											}
					else if (str.substr(0, 5) == "/event "){
						if (!canSB(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;
						cout << "Custom Event from " << ((PlayerInfo*)(peer->data))->rawName <<  " in world " << ((PlayerInfo*)(peer->data))->currentWorld << "with IP " << std::hex << peer->address.host << std::dec << " with message " << str.substr(5, cch.length() - 5 - 1) << endl;
						GamePacket p = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/large/special_event.rttex"), str.substr(4, cch.length() - 4 - 1).c_str()), "audio/pinata_lasso.wav"), 0));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						ENetPeer * currentPeer;
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							enet_peer_send(currentPeer, 0, packet);
						}
						
						//enet_host_flush(server);
						delete p.data;
					}
					else if (str == "/invis") {
					if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 333) {
						//sendConsoleMsg(peer, "`6" + str);
						if (pData->isinv == false) {

							pData->isinv = true;
							sendConsoleMsg(peer, "`oSilent,invisible,deadly.(`$Ninja Stealth `omod added)");
							ENetPeer* currentPeer;
							GamePacket p0 = packetEnd(appendInt(appendString(createPacket(), "OnInvis"), 1));

							memcpy(p0.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
							ENetPacket* packet0 = enet_packet_create(p0.data,
								p0.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet0);
							string text = "action|play_sfx\nfile|audio/boo_ghost_be_gone.wav\ndelayMS|0\n";
							BYTE* data = new BYTE[5 + text.length()];
							BYTE zero = 0;
							int type = 3;
							memcpy(data, &type, 4);
							memcpy(data + 4, text.c_str(), text.length());
							memcpy(data + 4 + text.length(), &zero, 1);
							ENetPacket* packet2 = enet_packet_create(data,
								5 + text.length(),
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet2);
							delete data;
							delete p0.data;


							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{


									((PlayerInfo*)(peer->data))->isinv = 1;
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnInvis"), 1));

									memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;




								}
							}

						}
						else {
							sendConsoleMsg(peer, "`oYou are less sneaky now.(`$Ninja Stealth `omod removed)");
							((PlayerInfo*)(peer->data))->skinColor = atoi("-155");

							GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnInvis"), 0));
							memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
							ENetPacket* packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet2);
							delete p2.data;



							pData->isinv = false;

							GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnNameChanged"), ((PlayerInfo*)(peer->data))->displayName));
							memcpy(p3.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4); // ffloor
							ENetPacket* packet3 = enet_packet_create(p3.data,
								p3.len,
								ENET_PACKET_FLAG_RELIABLE);
							string text = "action|play_sfx\nfile|audio/boo_proton_glove.wav\ndelayMS|0\n";
							BYTE* data = new BYTE[5 + text.length()];
							BYTE zero = 0;
							int type = 3;
							memcpy(data, &type, 4);
							memcpy(data + 4, text.c_str(), text.length());
							memcpy(data + 4 + text.length(), &zero, 1);
							ENetPacket* packet5 = enet_packet_create(data,
								5 + text.length(),
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet5);
							delete data;
							delete p3.data;

							ENetPeer* currentPeer;
							GamePacket penter1 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 92), ((PlayerInfo*)peer->data)->x1 + 10, ((PlayerInfo*)peer->data)->y1 + 15));
							GamePacket penter2 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 92), ((PlayerInfo*)peer->data)->x1 + 10, ((PlayerInfo*)peer->data)->y1 + 15));
							GamePacket penter3 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 92), ((PlayerInfo*)peer->data)->x1 + 10, ((PlayerInfo*)peer->data)->y1 + 15));
							GamePacket penter4 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 92), ((PlayerInfo*)peer->data)->x1 + 10, ((PlayerInfo*)peer->data)->y1 + 15));
							GamePacket penter8 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 92), ((PlayerInfo*)peer->data)->x1 + 10, ((PlayerInfo*)peer->data)->y1 + 15));
							GamePacket penter5 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 92), ((PlayerInfo*)peer->data)->x1 + 10, ((PlayerInfo*)peer->data)->y1 + 15));
							GamePacket penter6 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 92), ((PlayerInfo*)peer->data)->x1 + 10, ((PlayerInfo*)peer->data)->y1 + 15));
							GamePacket penter7 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 92), ((PlayerInfo*)peer->data)->x1 + 10, ((PlayerInfo*)peer->data)->y1 + 15));
							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									if (!((PlayerInfo*)(peer->data))->isGhost)
									{
										ENetPacket* packet5 = enet_packet_create(penter1.data,
											penter1.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(currentPeer, 0, packet5);

										ENetPacket* packet6 = enet_packet_create(penter2.data,
											penter2.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(currentPeer, 0, packet6);

										ENetPacket* packet7 = enet_packet_create(penter3.data,
											penter3.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(currentPeer, 0, packet7);

										ENetPacket* packet8 = enet_packet_create(penter4.data,
											penter4.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(currentPeer, 0, packet8);

										ENetPacket* packet9 = enet_packet_create(penter5.data,
											penter5.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(currentPeer, 0, packet9);

										ENetPacket* packet10 = enet_packet_create(penter6.data,
											penter6.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(currentPeer, 0, packet10);

										ENetPacket* packet11 = enet_packet_create(penter7.data,
											penter7.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(currentPeer, 0, packet11);

										ENetPacket* packet12 = enet_packet_create(penter8.data,
											penter8.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(currentPeer, 0, packet12);
										GamePacket pis = packetEnd(appendInt(appendString(createPacket(), "OnInvis"), 0));

										memcpy(pis.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
										ENetPacket* packetpis = enet_packet_create(pis.data,
											pis.len,
											ENET_PACKET_FLAG_RELIABLE);

										enet_peer_send(currentPeer, 0, packetpis);
										delete pis.data;
									}


									if (((PlayerInfo*)(peer->data))->rawName != ((PlayerInfo*)(currentPeer->data))->rawName)
									{
										enet_peer_send(currentPeer, 0, packet3);
									}
								}
							}

							sendState(peer);
							sendClothes(peer);
						}
					}
											}
					else if (str == "/max")
											{
											/*GamePacket p2ww = packetEnd(appendString(appendString(createPacket(), "OnCountryState"), ((PlayerInfo*)(peer->data))->country + "|maxLevel"));
											memcpy(p2ww.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
											ENetPacket * packet2ww = enet_packet_create(p2ww.data,
												p2ww.len,
												ENET_PACKET_FLAG_RELIABLE);

											enet_peer_send(currentPeer, 0, packet2ww);
											delete p2ww.data;
											GamePacket p2wwee = packetEnd(appendString(appendString(createPacket(), "OnCountryState"), ((PlayerInfo*)(currentPeer->data))->country + "|maxLevel"));
											memcpy(p2wwee.data + 8, &(((PlayerInfo*)(currentPeer->data))->netID), 4);
											ENetPacket * packet2wwee = enet_packet_create(p2wwee.data,
												p2wwee.len,
												ENET_PACKET_FLAG_RELIABLE);

											enet_peer_send(peer, 0, packet2wwee);
											delete p2wwee.data;

											((PlayerInfo*)(peer->data))->country = ((PlayerInfo*)(peer->data))->country + "|maxLevel";*/
											}
					
					else if (str.substr(0, 5) == "/asb ") {
					using namespace std::chrono;
					if (!isSuperAdmin(((PlayerInfo*)(event.peer->data))->rawName, ((PlayerInfo*)(event.peer->data))->tankIDPass)) continue;

					string name = ((PlayerInfo*)(peer->data))->displayName;

					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `4MOD-SB `0from `$`6" + name + "`0 (in `4HIDDEN!``) ** :`` `^ " + str.substr(4, cch.length() - 4 - 1)));
					string text = "action|play_sfx\nfile|audio/hub_open.wav\ndelayMS|0\n";
					BYTE* data = new BYTE[5 + text.length()];
					BYTE zero = 0;
					int type = 3;
					memcpy(data, &type, 4);
					memcpy(data + 4, text.c_str(), text.length());
					memcpy(data + 4 + text.length(), &zero, 1);
					ENetPeer* currentPeer;

					for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
					{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
							continue;
						if (!((PlayerInfo*)(currentPeer->data))->radio)
							continue;
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet);




						ENetPacket* packet2 = enet_packet_create(data,
							5 + text.length(),
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet2);

						//enet_host_flush(server);
					}
					delete data;
					delete p.data;
						}
					else if (str.substr(0, 5) == "/vsb ") {
					using namespace std::chrono;
					if (!canSB(((PlayerInfo*)(event.peer->data))->rawName, ((PlayerInfo*)(event.peer->data))->tankIDPass)) continue;

					string name = ((PlayerInfo*)(peer->data))->displayName;

					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `1VIP-SB `0from `$`6" + name + " `0(in `4HIDDEN!``) ** :`` `6 " + str.substr(4, cch.length() - 4 - 1)));
					string text = "action|play_sfx\nfile|audio/double_chance.wav\ndelayMS|0\n";
					BYTE* data = new BYTE[5 + text.length()];
					BYTE zero = 0;
					int type = 3;
					memcpy(data, &type, 4);
					memcpy(data + 4, text.c_str(), text.length());
					memcpy(data + 4 + text.length(), &zero, 1);
					ENetPeer* currentPeer;

					for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
					{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
							continue;
						if (!((PlayerInfo*)(currentPeer->data))->radio)
							continue;
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet);




						ENetPacket* packet2 = enet_packet_create(data,
							5 + text.length(),
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet2);

						//enet_host_flush(server);
					}
					delete data;
					delete p.data;
						}
					else if (str.substr(0, 3) == "/m ") {
					if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666) {
						using namespace std::chrono;
						string name = ((PlayerInfo*)(peer->data))->displayName;
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`r[MOD CHAT] `2" + ((PlayerInfo*)(peer->data))->tankIDName + "`r(" + ((PlayerInfo*)(peer->data))->displayName + "`r): `6" + str.substr(3, cch.length() - 3 - 1)));
						string text = "action|play_sfx\nfile|audio/beep.wav\ndelayMS|0\n";
						BYTE* data = new BYTE[5 + text.length()];
						BYTE zero = 0;
						int type = 3;
						memcpy(data, &type, 4);
						memcpy(data + 4, text.c_str(), text.length());
						memcpy(data + 4 + text.length(), &zero, 1);
						ENetPeer* currentPeer;

						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							if (!((PlayerInfo*)(currentPeer->data))->radio)
								continue;
							if (getAdminLevel(((PlayerInfo*)(currentPeer->data))->rawName, ((PlayerInfo*)(currentPeer->data))->tankIDPass) == 999 || getAdminLevel(((PlayerInfo*)(currentPeer->data))->rawName, ((PlayerInfo*)(currentPeer->data))->tankIDPass) == 666) {
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(currentPeer, 0, packet);




								ENetPacket* packet2 = enet_packet_create(data,
									5 + text.length(),
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(currentPeer, 0, packet2);

								//enet_host_flush(server);
							}
						}
						delete data;
						delete p.data;
					}
											}
					else if (str.substr(0, 5) == "/ssb ") {
					using namespace std::chrono;
					if (((PlayerInfo*)(peer->data))->boughtFYE == false)
					{
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4ERROR `w>> You need to buy `6Dark Hammer `wbefore u can do /ssb!"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
					}

					else
					{
						string name = ((PlayerInfo*)(peer->data))->displayName;
						GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "You received `2Special - Broadcast`` From `6" + name + ""));
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `2Special - Broadcast`` from `$`6" + name + "```0 (in `6" + ((PlayerInfo*)(peer->data))->currentWorld + "`0) ** :`` `$ " + str.substr(5, cch.length() - 5 - 1)));
						string text = "action|play_sfx\nfile|audio/double_chance.wav\ndelayMS|0\n";
						BYTE* data = new BYTE[5 + text.length()];
						BYTE zero = 0;
						int type = 3;
						memcpy(data, &type, 4);
						memcpy(data + 4, text.c_str(), text.length());
						memcpy(data + 4 + text.length(), &zero, 1);
						ENetPeer* currentPeer;

						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							if (!((PlayerInfo*)(currentPeer->data))->radio)
								continue;
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							ENetPacket* packet2 = enet_packet_create(data,
								5 + text.length(),
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(currentPeer, 0, packet2);

							//enet_host_flush(server);
							enet_peer_send(currentPeer, 0, packet);
							ENetPacket* packet3 = enet_packet_create(p3.data,
								p3.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(currentPeer, 0, packet3);

							//enet_host_flush(server);

						}
						delete data;
						delete p.data;
						delete p3.data;
					}
											}
					else if (str == "/gsm ") {


					if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999) {
						cout << "GSM from " << ((PlayerInfo*)(peer->data))->rawName << " in world " << ((PlayerInfo*)(peer->data))->currentWorld << "with IP " << std::hex << peer->address.host << std::dec << " with message " << str.substr(5, cch.length() - 5 - 1) << endl;
						string name = ((PlayerInfo*)(peer->data))->displayName;

						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Global System Message: `o" + str.substr(4, cch.length() - 4 - 1)));
						string text = "action|play_sfx\nfile|audio/sungate.wav\ndelayMS|0\n";
						BYTE* data = new BYTE[5 + text.length()];
						BYTE zero = 0;
						int type = 3;
						memcpy(data, &type, 4);
						memcpy(data + 4, text.c_str(), text.length());
						memcpy(data + 4 + text.length(), &zero, 1);
						ENetPeer* currentPeer;

						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							if (!((PlayerInfo*)(currentPeer->data))->radio)
								continue;
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(currentPeer, 0, packet);



							ENetPacket* packet2 = enet_packet_create(data,
								5 + text.length(),
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(currentPeer, 0, packet2);

							//enet_host_flush(server);
						}
						delete data;
						delete p.data;
					}
												}
					else if (str.substr(0, 4) == "/sb ") {
						using namespace std::chrono;
						if (((PlayerInfo*)(peer->data))->lastSB + 45000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
						{
							((PlayerInfo*)(peer->data))->lastSB = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
						}
						else {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Wait a minute before using the SB command again!"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet);
							delete p.data;
							//enet_host_flush(server);
							continue;
						}

						string name = ((PlayerInfo*)(peer->data))->displayName;
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `5Super-Broadcast`` from `$`2" + name + "```` (in `$" + ((PlayerInfo*)(peer->data))->currentWorld + "``) ** :`` `# " + str.substr(4, cch.length() - 4 - 1)));
						string text = "action|play_sfx\nfile|audio/beep.wav\ndelayMS|0\n";
						BYTE* data = new BYTE[5 + text.length()];
						BYTE zero = 0;
						int type = 3;
						memcpy(data, &type, 4);
						memcpy(data + 4, text.c_str(), text.length());
						memcpy(data + 4 + text.length(), &zero, 1);
						ENetPeer * currentPeer;
						
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							if (!((PlayerInfo*)(currentPeer->data))->radio)
								continue;
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(currentPeer, 0, packet);
							
							
							
							
							ENetPacket * packet2 = enet_packet_create(data,
								5+text.length(),
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(currentPeer, 0, packet2);
							
							//enet_host_flush(server);
						}
						delete data;
						delete p.data;
					}
					else if (str.substr(0, 5) == "/jsb ") {
						using namespace std::chrono;
						if (((PlayerInfo*)(peer->data))->lastSB + 45000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
						{
							((PlayerInfo*)(peer->data))->lastSB = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
						}
						else {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Wait a minute before using the JSB command again!"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet);
							delete p.data;
							//enet_host_flush(server);
							continue;
						}

						string name = ((PlayerInfo*)(peer->data))->displayName;
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w** `5Super-Broadcast`` from `$`2" + name + "```` (in `4JAMMED``) ** :`` `# " + str.substr(5, cch.length() - 5 - 1)));
						string text = "action|play_sfx\nfile|audio/beep.wav\ndelayMS|0\n";
						BYTE* data = new BYTE[5 + text.length()];
						BYTE zero = 0;
						int type = 3;
						memcpy(data, &type, 4);
						memcpy(data + 4, text.c_str(), text.length());
						memcpy(data + 4 + text.length(), &zero, 1);
						ENetPeer * currentPeer;
						
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							if (!((PlayerInfo*)(currentPeer->data))->radio)
								continue;
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(currentPeer, 0, packet);
							
							
							
							
							ENetPacket * packet2 = enet_packet_create(data,
								5+text.length(),
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(currentPeer, 0, packet2);
							
							//enet_host_flush(server);
						}
						delete data;
						delete p.data;
					}
					else if (str.substr(0, 3) == "/v ") {
					if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 333) {
						using namespace std::chrono;

						string name = ((PlayerInfo*)(peer->data))->displayName;
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`3[VIP CHAT] `2" + ((PlayerInfo*)(peer->data))->tankIDName + "`3(" + ((PlayerInfo*)(peer->data))->displayName + "`3): `6" + str.substr(3, cch.length() - 3 - 1)));
						ENetPeer* currentPeer;

						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							if (!((PlayerInfo*)(currentPeer->data))->radio)
								continue;
							if (getAdminLevel(((PlayerInfo*)(currentPeer->data))->rawName, ((PlayerInfo*)(currentPeer->data))->tankIDPass) == 333 || getAdminLevel(((PlayerInfo*)(currentPeer->data))->rawName, ((PlayerInfo*)(currentPeer->data))->tankIDPass) == 666 || getAdminLevel(((PlayerInfo*)(currentPeer->data))->rawName, ((PlayerInfo*)(currentPeer->data))->tankIDPass) == 999) {
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(currentPeer, 0, packet);

								//enet_host_flush(server);
							}
						}

						delete p.data;
					}
											}
					
					else if (str.substr(0, 6) == "/radio") {
						GamePacket p;
						if (((PlayerInfo*)(peer->data))->radio) {
							p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You won't see broadcasts anymore."));
							((PlayerInfo*)(peer->data))->radio = false;
						} else {
							p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You will now see broadcasts again."));
							((PlayerInfo*)(peer->data))->radio = true;
						}

						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet);
						delete p.data;
						//enet_host_flush(server);
					}
					else if (str.substr(0, 6) == "/restart"){
						if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
						cout << "Restart from " << ((PlayerInfo*)(peer->data))->displayName << endl;
						GamePacket p = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/science_button.rttex"), "Restarting soon!"), "audio/mp3/suspended.mp3"), 0));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						ENetPeer * currentPeer;
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							enet_peer_send(currentPeer, 0, packet);
						}
						delete p.data;
						//enet_host_flush(server);
					}
					else if (str == "/party") {
						if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
						cout << "Party From  " << ((PlayerInfo*)(peer->data))->displayName << endl;
						GamePacket p = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/science_button.rttex"), "Party Guys !!"), "audio/mp3/suspended.mp3"), 0));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						ENetPeer* currentPeer;
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							enet_peer_send(currentPeer, 0, packet);
						}
						delete p.data;
						//enet_host_flush(server);
					}

					else if (str.substr(0, 6) == "/clear") {
					if (((PlayerInfo*)(peer->data))->rawName == world->owner || isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) {

						WorldInfo* wrld = getPlyersWorld(peer);

						ENetPeer* currentPeer;
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							if (((PlayerInfo*)(currentPeer->data))->currentWorld == wrld->name)
							{
								string act = ((PlayerInfo*)(peer->data))->currentWorld;
								//WorldInfo info = worldDB.get(act);
								// sendWorld(currentPeer, &info);
								int x = 3040;
								int y = 736;



								for (int i = 0; i < world->width * world->height; i++)
								{
									if (world->items[i].foreground == 6) {
										//world->items[i].foreground =0;
									}
									else if (world->items[i].foreground == 8) {

									}
									else if (world->items[i].foreground == 242) {

									}
									else {
										world->items[i].foreground = 0;
										world->items[i].background = 0;
									}
								}
								sendPlayerLeave(currentPeer, (PlayerInfo*)(currentPeer->data));
								joinWorld(currentPeer, act, 0, 0);





							}

						}
					}
					}
					/*else if (str.substr(0, 7) == "/clear "){
							if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) continue;
							cout << "World cleared by " << ((PlayerInfo*)(peer->data))->tankIDName << endl;
							WorldInfo* wrld = getPlyersWorld(peer);
							string wName = str.substr(4, cch.length() - 4 - 1);
							for (auto & c : wName) c = toupper(c);
							for (int i = 0; i < worlds.size(); i++)
							{
								if (wrld == NULL) continue;
								if (wName == wrld->name)
								{
									worlds.at(i) = generateWorld(wrld->name, wrld->width, wrld->height);
									ENetPeer * currentPeer;
									for (currentPeer = server->peers;
										currentPeer < &server->peers[server->peerCount];
										++currentPeer)
									{
										if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
											continue;
										if (((PlayerInfo*)(currentPeer->data))->currentWorld == world->name)
										{
											sendWorld(currentPeer, &worlds.at(i));

											int x = 3040;
											int y = 736;

											for (int j = 0; j < worlds.at(i).width*worlds.at(i).height; j++)
											{
												if (worlds.at(i).items[j].foreground == 6) {
													x = (j%worlds.at(i).width) * 32;
													y = (j / worlds.at(i).width) * 32;
												}
											}
											GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + std::to_string(cId) + "\nuserID|" + std::to_string(cId) + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(x) + "|" + std::to_string(y) + "\nname|``" + ((PlayerInfo*)(currentPeer->data))->tankIDName + "``\ncountry|" + ((PlayerInfo*)(currentPeer->data))->country + "\ninvis|0\nmstate|0\nsmstate|0\ntype|local\n"));
											//for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";
											ENetPacket * packet = enet_packet_create(p.data,
												p.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(currentPeer, 0, packet);

											enet_host_flush(server);
											delete p.data;
											((PlayerInfo*)(currentPeer->data))->netID = cId;
											onPeerConnect(currentPeer);
											cId++;

											sendInventory(((PlayerInfo*)(event.peer->data))->inventory);
										}

									}
									enet_host_flush(server);
								}
							}
						}*/






					else if (str == "/unmod")
						{
						((PlayerInfo*)(peer->data))->skinColor = 0x8295C3FF;
						((PlayerInfo*)(peer->data))->canWalkInBlocks = false;
						sendState(peer);
						sendClothes(peer);
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oModerator mode has been `4disabled`o! You will not able to walk through blocks!``"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						ENetPeer* currentPeer;
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
						}
						string text = "action|play_sfx\nfile|audio/dialog_cancel.wav\ndelayMS|0\n";
						BYTE* data = new BYTE[5 + text.length()];
						BYTE zero = 0;
						int type = 3;
						memcpy(data, &type, 4);
						memcpy(data + 4, text.c_str(), text.length());
						memcpy(data + 4 + text.length(), &zero, 1);
						ENetPacket* packet2 = enet_packet_create(data,
							5 + text.length(),
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet2);
						enet_peer_send(peer, 0, packet2);
						delete p.data;
						delete data;
						/*PlayerMoving data;
						data.packetType = 0x14;
						data.characterState = 0x0; // animation
						data.x = 1000;
						data.y = 1;
						data.punchX = 0;
						data.punchY = 0;
						data.XSpeed = 300;
						data.YSpeed = 600;
						data.netID = ((PlayerInfo*)(peer->data))->netID;
						data.plantingTree = 0x0;
						SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);*/
						}
					else if (str == "/beta") {
						GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetBetaMode"), 1));
						ENetPacket * packet2 = enet_packet_create(p2.data,
						p2.len,
						ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet2);
						delete p2.data;
						//enet_host_flush(server);
					}
					else
					if (str == "/inventory")
					{
						sendInventory(peer, ((PlayerInfo*)(peer->data))->inventory);
					} else
					if (str.substr(0,6) == "/item ")
					{
						PlayerInventory inventory;
						InventoryItem item;
						item.itemID = atoi(str.substr(6, cch.length() - 6 - 1).c_str());
						item.itemCount = 200;
						inventory.items.push_back(item);
						item.itemCount = 1;
						item.itemID = 18;
						inventory.items.push_back(item);
						item.itemID = 32;
						inventory.items.push_back(item);
						sendInventory(peer, inventory);
					} else
					if (str.substr(0, 6) == "/team ")
					{
						int val = 0;
						val = atoi(str.substr(6, cch.length() - 6 - 1).c_str());
						PlayerMoving data;
						//data.packetType = 0x14;
						data.packetType = 0x1B;
						//data.characterState = 0x924; // animation
						data.characterState = 0x0; // animation
						data.x = 0;
						data.y = 0;
						data.punchX = val;
						data.punchY = 0;
						data.XSpeed = 0;
						data.YSpeed = 0;
						data.netID = ((PlayerInfo*)(peer->data))->netID;
						data.plantingTree = 0;
						SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);

					} else 
					if (str.substr(0, 7) == "/color ")
					{
						((PlayerInfo*)(peer->data))->skinColor = atoi(str.substr(6, cch.length() - 6 - 1).c_str());
						sendClothes(peer);
					}
					if (str.substr(0, 4) == "/who")
					{
						sendWho(peer);

					}
					if (str.length() && str[0] == '/')
					{
						sendAction(peer, ((PlayerInfo*)(peer->data))->netID, str);
					} else if (str.length()>0)
					{
						if (((PlayerInfo*)(peer->data))->taped == false) {
							sendChatMessage(peer, ((PlayerInfo*)(peer->data))->netID, str);
						}
						else {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Cant talk while you are ducttaped!"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
					}
					
			    }
				if (!((PlayerInfo*)(event.peer->data))->isIn)
				{
					GamePacket p = packetEnd(appendString(appendString(appendString(appendString(appendInt(appendString(createPacket(), "OnSuperMainStartAcceptLogonHrdxs47254722215a"), itemdathash), "ubistatic-a.akamaihd.net"), "0098/CDNContent26/cache/"), "cc.cz.madkite.freedom org.aqua.gg idv.aqua.bulldog com.cih.gamecih2 com.cih.gamecih com.cih.game_cih cn.maocai.gamekiller com.gmd.speedtime org.dax.attack com.x0.strai.frep com.x0.strai.free org.cheatengine.cegui org.sbtools.gamehack com.skgames.traffikrider org.sbtoods.gamehaca com.skype.ralder org.cheatengine.cegui.xx.multi1458919170111 com.prohiro.macro me.autotouch.autotouch com.cygery.repetitouch.free com.cygery.repetitouch.pro com.proziro.zacro com.slash.gamebuster"), "proto=42|choosemusic=audio/ogg/theme4.ogg|active_holiday=0|"));
					//for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";
					ENetPacket * packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);
					
					//enet_host_flush(server);
					delete p.data;
					std::stringstream ss(GetTextPointerFromPacket(event.packet));
					std::string to;
					while (std::getline(ss, to, '\n')){
						string id = to.substr(0, to.find("|"));
						string act = to.substr(to.find("|") + 1, to.length() - to.find("|") - 1);
						if (id == "tankIDName")
						{
							((PlayerInfo*)(event.peer->data))->tankIDName = act;
							((PlayerInfo*)(event.peer->data))->haveGrowId = true;
						}
						else if(id == "tankIDPass")
						{
							((PlayerInfo*)(event.peer->data))->tankIDPass = act;
						}
						else if(id == "requestedName")
						{
							((PlayerInfo*)(event.peer->data))->requestedName = act;
						}
						else if (id == "country")
						{
							((PlayerInfo*)(event.peer->data))->country = act;
						}
					}
					if (!((PlayerInfo*)(event.peer->data))->haveGrowId)
					{
						((PlayerInfo*)(event.peer->data))->rawName = "";
						((PlayerInfo*)(event.peer->data))->displayName = "`w(`9Guest`w) " + PlayerDB::fixColors(((PlayerInfo*)(event.peer->data))->requestedName.substr(0, ((PlayerInfo*)(event.peer->data))->requestedName.length()>15?15:((PlayerInfo*)(event.peer->data))->requestedName.length()));
					}
					else {
						((PlayerInfo*)(event.peer->data))->rawName = PlayerDB::getProperName(((PlayerInfo*)(event.peer->data))->tankIDName);
#ifdef REGISTRATION
						int logStatus = PlayerDB::playerLogin(peer, ((PlayerInfo*)(event.peer->data))->rawName, ((PlayerInfo*)(event.peer->data))->tankIDPass);
						if (logStatus == -32) {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`wThat name is Currently being Used by the `rSystem`w."));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;

							enet_peer_disconnect_later(peer, 0);
						}
						if (logStatus == 1) {
							bool b = false;
							std::ifstream ifs("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json");
							if (ifs.is_open()) {
								json x;
								ifs >> x;
								if (x["banned"])
									b = true;
							}
							if (b) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Sorry, this account (`5" + ((PlayerInfo*)(peer->data))->rawName + "`4) has been suspended. Please contact: Luc1Fer#1337 Or Valkrie#1234 on Discord"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
								enet_peer_disconnect_later(peer, 0);
							}
							else {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`2Logging on.. `w[`5GrowtopiaFX `cV1.0 `w(`bC`w) `92019`w]"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
								((PlayerInfo*)(event.peer->data))->displayName = ((PlayerInfo*)(event.peer->data))->tankIDName;
						}
					}
						else {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`rWrong username or password!``"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
							enet_peer_disconnect_later(peer, 0);
						}
#else
						
						((PlayerInfo*)(event.peer->data))->displayName = PlayerDB::fixColors(((PlayerInfo*)(event.peer->data))->tankIDName.substr(0, ((PlayerInfo*)(event.peer->data))->tankIDName.length()>18 ? 18 : ((PlayerInfo*)(event.peer->data))->tankIDName.length()));
						if (((PlayerInfo*)(event.peer->data))->displayName.length() < 3) ((PlayerInfo*)(event.peer->data))->displayName = "Person that doesn't know how the name looks!";
#endif
					}
					for (char c : ((PlayerInfo*)(event.peer->data))->displayName) if (c < 0x20 || c>0x7A) ((PlayerInfo*)(event.peer->data))->displayName = "Bad characters in name, remove them!";
					if (isVIP(((PlayerInfo*)(event.peer->data))->rawName, ((PlayerInfo*)(event.peer->data))->tankIDPass) > 0) {
						((PlayerInfo*)(event.peer->data))->displayName = "`e@" + ((PlayerInfo*)(event.peer->data))->tankIDName;
					}
					if (isMod(((PlayerInfo*)(event.peer->data))->rawName, ((PlayerInfo*)(event.peer->data))->tankIDPass) > 0) {
						((PlayerInfo*)(event.peer->data))->displayName = "`#@" + ((PlayerInfo*)(event.peer->data))->tankIDName;
					}
					if (isSuperAdmin(((PlayerInfo*)(event.peer->data))->rawName, ((PlayerInfo*)(event.peer->data))->tankIDPass) > 0) {
						((PlayerInfo*)(event.peer->data))->displayName = "`6@" + ((PlayerInfo*)(event.peer->data))->tankIDName;
					}
					if (((PlayerInfo*)(peer->data))->boughtFYE == true)
					{
						((PlayerInfo*)(event.peer->data))->displayName = "`w[`9S`4P`2E`8C`1I`6A`bL`w] " + ((PlayerInfo*)(event.peer->data))->tankIDName;
					}
					if (((PlayerInfo*)(event.peer->data))->country.length() > 4)
					{
						((PlayerInfo*)(event.peer->data))->country = "us";
					}


					if (isSuperAdmin(((PlayerInfo*)(event.peer->data))->rawName, ((PlayerInfo*)(event.peer->data))->tankIDPass) > 0)
					{
						((PlayerInfo*)(event.peer->data))->country = "../rtsoft_flag";
					}
					if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999 && ((PlayerInfo*)(peer->data))->rawName == "luc1fer")
					{

						((PlayerInfo*)(peer->data))->country = "/rtsoft_logo";
					}
					else if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999)
					{

						((PlayerInfo*)(peer->data))->country = "/atomic_button";
					}
					else if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666)
					{

						((PlayerInfo*)(peer->data))->country = "/particle_star";
					}
					/*GamePacket p3= packetEnd(appendString(appendString(createPacket(), "OnRequestWorldSelectMenu"), "default|GO FOR IT\nadd_button|Showing: `wFake Worlds``|_catselect_|0.6|3529161471|\nadd_floater|Subscribe|5|0.55|3529161471\nadd_floater|Growtopia|4|0.52|4278190335\nadd_floater|Noobs|150|0.49|3529161471\nadd_floater|...|3|0.49|3529161471\nadd_floater|`6:O :O :O``|2|0.46|3529161471\nadd_floater|SEEMS TO WORK|2|0.46|3529161471\nadd_floater|?????|1|0.43|3529161471\nadd_floater|KEKEKEKEK|13|0.7|3417414143\n"));
					//for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";
					ENetPacket * packet3 = enet_packet_create(p3.data,
						p3.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet3);
					enet_host_flush(server);*/

					GamePacket p2 = packetEnd(appendString(appendString(appendInt(appendString(createPacket(), "SetHasGrowID"), ((PlayerInfo*)(event.peer->data))->haveGrowId), ((PlayerInfo*)(peer->data))->tankIDName), ((PlayerInfo*)(peer->data))->tankIDPass));
					ENetPacket * packet2 = enet_packet_create(p2.data,
						p2.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet2);
					delete p2.data;

					
				}
				string pStr = GetTextPointerFromPacket(event.packet);
				//if (strcmp(GetTextPointerFromPacket(event.packet), "action|enter_game\n") == 0 && !((PlayerInfo*)(event.peer->data))->isIn)
				if(pStr.substr(0, 17) == "action|enter_game" && !((PlayerInfo*)(event.peer->data))->isIn)
				{
#ifdef TOTAL_LOG
					cout << "And we are in!" << endl;
#endif
					ENetPeer* currentPeer;
					((PlayerInfo*)(event.peer->data))->isIn = true;
					/*for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
					{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
							continue;

						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Player `o" + ((PlayerInfo*)(event.peer->data))->tankIDName + "`o just entered the game..."));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(currentPeer, 0, packet);
						
						enet_host_flush(server);
						delete p.data;
					}*/
					sendWorldOffers(peer);
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`oServer Made by `6Luc1Fer `o(Luc1Fer#1337), And `6Valkrie `o(Valkrie#1234)."));
					ENetPacket* packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);

					//enet_host_flush(server);
					delete p.data;
					PlayerInventory inventory;
					for (int i = 0; i < 200; i++)
					{
						InventoryItem it;
						it.itemID = (i * 2) + 2;
						it.itemCount = 200;
						inventory.items.push_back(it);
					}
					((PlayerInfo*)(event.peer->data))->inventory = inventory;

					{
						//GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wThe Growtopia Gazette``|left|5016|\n\nadd_spacer|small|\n\nadd_image_button|banner|interface/large/news_banner.rttex|noflags|||\n\nadd_spacer|small|\n\nadd_textbox|`wSeptember 10:`` `5Surgery Stars end!``|left|\n\nadd_spacer|small|\n\n\n\nadd_textbox|Hello Growtopians,|left|\n\nadd_spacer|small|\n\n\n\nadd_textbox|Surgery Stars is over! We hope you enjoyed it and claimed all your well-earned Summer Tokens!|left|\n\nadd_spacer|small|\n\nadd_spacer|small|\n\nadd_textbox|As we announced earlier, this month we are releasing the feature update a bit later, as we're working on something really cool for the monthly update and we're convinced that the wait will be worth it!|left|\n\nadd_spacer|small|\n\nadd_textbox|Check the Forum here for more information!|left|\n\nadd_spacer|small|\n\nadd_url_button|comment|`wSeptember Updates Delay``|noflags|https://www.growtopiagame.com/forums/showthread.php?510657-September-Update-Delay&p=3747656|Open September Update Delay Announcement?|0|0|\n\nadd_spacer|small|\n\nadd_spacer|small|\n\nadd_textbox|Also, we're glad to invite you to take part in our official Growtopia survey!|left|\n\nadd_spacer|small|\n\nadd_url_button|comment|`wTake Survey!``|noflags|https://ubisoft.ca1.qualtrics.com/jfe/form/SV_1UrCEhjMO7TKXpr?GID=26674|Open the browser to take the survey?|0|0|\n\nadd_spacer|small|\n\nadd_textbox|Click on the button above and complete the survey to contribute your opinion to the game and make Growtopia even better! Thanks in advance for taking the time, we're looking forward to reading your feedback!|left|\n\nadd_spacer|small|\n\nadd_spacer|small|\n\nadd_textbox|And for those who missed PAW, we made a special video sneak peek from the latest PAW fashion show, check it out on our official YouTube channel! Yay!|left|\n\nadd_spacer|small|\n\nadd_url_button|comment|`wPAW 2018 Fashion Show``|noflags|https://www.youtube.com/watch?v=5i0IcqwD3MI&feature=youtu.be|Open the Growtopia YouTube channel for videos and tutorials?|0|0|\n\nadd_spacer|small|\n\nadd_textbox|Lastly, check out other September updates:|left|\n\nadd_spacer|small|\n\nadd_label_with_icon|small|IOTM: The Sorcerer's Tunic of Mystery|left|24|\n\nadd_label_with_icon|small|New Legendary Summer Clash Branch|left|24|\n\nadd_spacer|small|\n\nadd_textbox|`$- The Growtopia Team``|left|\n\nadd_spacer|small|\n\nadd_spacer|small|\n\n\n\n\n\nadd_url_button|comment|`wOfficial YouTube Channel``|noflags|https://www.youtube.com/c/GrowtopiaOfficial|Open the Growtopia YouTube channel for videos and tutorials?|0|0|\n\nadd_url_button|comment|`wSeptember's IOTM: `8Sorcerer's Tunic of Mystery!````|noflags|https://www.growtopiagame.com/forums/showthread.php?450065-Item-of-the-Month&p=3392991&viewfull=1#post3392991|Open the Growtopia website to see item of the month info?|0|0|\n\nadd_spacer|small|\n\nadd_label_with_icon|small|`4WARNING:`` `5Drop games/trust tests`` and betting games (like `5Casinos``) are not allowed and will result in a ban!|left|24|\n\nadd_label_with_icon|small|`4WARNING:`` Using any kind of `5hacked client``, `5spamming/text pasting``, or `5bots`` (even with an alt) will likely result in losing `5ALL`` your accounts. Seriously.|left|24|\n\nadd_label_with_icon|small|`4WARNING:`` `5NEVER enter your GT password on a website (fake moderator apps, free gemz, etc) - it doesn't work and you'll lose all your stuff!|left|24|\n\nadd_spacer|small|\n\nadd_url_button|comment|`wGrowtopia on Facebook``|noflags|http://growtopiagame.com/facebook|Open the Growtopia Facebook page in your browser?|0|0|\n\nadd_spacer|small|\n\nadd_button|rules|`wHelp - Rules - Privacy Policy``|noflags|0|0|\n\n\nadd_quick_exit|\n\nadd_spacer|small|\nadd_url_button|comment|`wVisit Growtopia Forums``|noflags|http://www.growtopiagame.com/forums|Visit the Growtopia forums?|0|0|\nadd_spacer|small|\nadd_url_button||`wWOTD: `1THELOSTGOLD`` by `#iWasToD````|NOFLAGS|OPENWORLD|THELOSTGOLD|0|0|\nadd_spacer|small|\nadd_url_button||`wVOTW: `1Yodeling Kid - Growtopia Animation``|NOFLAGS|https://www.youtube.com/watch?v=UMoGmnFvc58|Watch 'Yodeling Kid - Growtopia Animation' by HyerS on YouTube?|0|0|\nend_dialog|gazette||OK|"));
						GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wGrowtopiaFX``|left|2252|\n\nadd_spacer|small|\nadd_label_with_icon|small|\nadd_button|crash|`w[`4Fix Crash`w] `eRemove Clothes|noflags|0|0|\n\nadd_image_button|banner|interface/large/news_banner.rttex|noflags|||\nadd_textbox|`wDecember 26: `5GTFX Update!|left|6746|\nadd_spacer|small|\nadd_textbox|`wDear GrowtopiaFX Players:|\nadd_textbox|`9Christmas has Ended! We would love to wish you all a Happy new year!|\nadd_spacer|small|\nadd_textbox|`w- The GrowtopiaFX Team|\nadd_spacer|small|\nadd_url_button||`9Join our Discord``|NOFLAGS|https://discord.gg/HhGsqws|Open link?|0|0| |left|6746|\nadd_spacer|small|\nadd_label_with_icon|small|`4WARNING:`` `5Worlds And Accounts might be deleted at any time if database issues appear (once per day or week).|left|1432|\nadd_label_with_icon|small|`4WARNING:`` `5Accounts`` are in beta, bugs may appear and they will be probably deleted often, because of new accounts updates, which will cause database incompatibility.|left|1432|\nadd_spacer|small|\nadd_textbox|`4WARNING: `wDon't Forget to Follow the `4/Rules`w.|\nadd_spacer|small|\nadd_button|closenews|`9Continue|"));
						ENetPacket* packet3 = enet_packet_create(p3.data,
							p3.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet3);
						string text = "action|play_sfx\nfile|audio/choir.wav\ndelayMS|0\n";
						BYTE* data = new BYTE[5 + text.length()];
						BYTE zero = 0;
						int type = 3;
						memcpy(data, &type, 4);
						memcpy(data + 4, text.c_str(), text.length());
						memcpy(data + 4 + text.length(), &zero, 1);
						ENetPacket* packet5 = enet_packet_create(data,
							5 + text.length(),
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(peer, 0, packet5);
						delete p3.data;
						delete data;
					}
				}
				if (strcmp(GetTextPointerFromPacket(event.packet), "action|refresh_item_data\n") == 0)
				{
					if (itemsDat != NULL) {
						ENetPacket * packet = enet_packet_create(itemsDat,
							itemsDatSize + 60,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						((PlayerInfo*)(peer->data))->isUpdating = true;
						enet_peer_disconnect_later(peer, 0);
						//enet_host_flush(server);
					}
					// TODO FIX refresh_item_data ^^^^^^^^^^^^^^
				}
				break;
			}
			default:
				cout << "Unknown packet type " << messageType << endl;
				break;
			case 3:
			{
				//cout << GetTextPointerFromPacket(event.packet) << endl;
				std::stringstream ss(GetTextPointerFromPacket(event.packet));
				std::string to;
				bool isJoinReq = false;
				bool isNukedx = false;
				while (std::getline(ss, to, '\n')) {
					string id = to.substr(0, to.find("|"));
					string act = to.substr(to.find("|") + 1, to.length() - to.find("|") - 1);
					if (id == "name" && isJoinReq)
					{
#ifdef TOTAL_LOG
						cout << "Entering some world..." << endl;
#endif
						try {
							WorldInfo info = worldDB.get(act);
							sendWorld(peer, &info);
							/*string asdf = "0400000004A7379237BB2509E8E0EC04F8720B050000000000000000FBBB0000010000007D920100FDFDFDFD04000000040000000000000000000000070000000000"; // 0400000004A7379237BB2509E8E0EC04F8720B050000000000000000FBBB0000010000007D920100FDFDFDFD04000000040000000000000000000000080000000000000000000000000000000000000000000000000000000000000048133A0500000000BEBB0000070000000000
							string worldName = "TEST";
							int xSize=100;
							int ySize=60;
							int square = xSize*ySize;
							__int16 nameLen = worldName.length();
							int payloadLen = asdf.length() / 2;
							int dataLen = payloadLen + 2 + nameLen + 12 + (square * 8)+4;
							BYTE* data = new BYTE[dataLen];
							for (int i = 0; i < asdf.length(); i += 2)
							{
							char x = ch2n(asdf[i]);
							x = x << 4;
							x += ch2n(asdf[i + 1]);
							memcpy(data + (i / 2), &x, 1);
							}
							int zero = 0;
							__int16 item = 0;
							int smth = 0;
							for (int i = 0; i < square * 8; i += 4) memcpy(data + payloadLen + i + 14 + nameLen, &zero, 4);
							for (int i = 0; i < square * 8; i += 8) memcpy(data + payloadLen + i + 14 + nameLen, &item, 2);
							memcpy(data + payloadLen, &nameLen, 2);
							memcpy(data + payloadLen + 2, worldName.c_str(), nameLen);
							memcpy(data + payloadLen + 2 + nameLen, &xSize, 4);
							memcpy(data + payloadLen + 6 + nameLen, &ySize, 4);
							memcpy(data + payloadLen + 10 + nameLen, &square, 4);
							for (int i = 0; i < 1700; i++) {
							__int16 bed = 100;
							memcpy(data + payloadLen + (i * 8) + 14 + nameLen + (8 * 100 * 37), &bed, 2);
							}
							for (int i = 0; i < 600; i++) {
							__int16 bed = 8;
							memcpy(data + payloadLen + (i*8) + 14 + nameLen + (8*100*54), &bed, 2);
							}
							memcpy(data + dataLen-4, &smth, 4);
							ENetPacket * packet2 = enet_packet_create(data,
							dataLen,
							ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet2);
							enet_host_flush(server);*/

							int x = 3040;
							int y = 736;

							for (int j = 0; j < info.width*info.height; j++)
							{
								if (info.items[j].foreground == 6) {
									x = (j%info.width) * 32;
									y = (j / info.width) * 32;
								}
							}
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + std::to_string(cId) + "\nuserID|" + std::to_string(cId) + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(x) + "|" + std::to_string(y) + "\nname|``" + ((PlayerInfo*)(event.peer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(event.peer->data))->country + "\ninvis|0\nmstate|0\nsmstate|0\ntype|local\n"));
							//for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							//enet_host_flush(server);
							delete p.data;
							((PlayerInfo*)(event.peer->data))->netID = cId;
							onPeerConnect(peer);
							cId++;

							sendInventory(peer, ((PlayerInfo*)(event.peer->data))->inventory);
							WorldInfo* world = getPlyersWorld(peer);
							string nameworld = world->name;
							string ownerworld = world->owner;
							int count = 0;
							string name = "";
							ENetPeer* currentPeer;
							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								count++;
							}
							sendPlayerEnter(peer, (PlayerInfo*)(event.peer->data));
							if (ownerworld != "") {
								GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`#[`o" + nameworld + " `oWorld Locked by " + ownerworld + "`#]"));
								ENetPacket* packet3 = enet_packet_create(p3.data,
									p3.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet3);
								delete p3.data;
							}
							WorldInfo* real = getPlyersWorld(peer);
							GamePacket paczka = packetEnd(appendInt(appendString(createPacket(), "OnSetBaseWeather"), real->weather));
							ENetPacket* packetpaka = enet_packet_create(paczka.data,
								paczka.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packetpaka);
							delete paczka.data;
							//
							PlayerInfo* playinfo = ((PlayerInfo*)(peer->data));
							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								int var = 0x808000; // placing and breking
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer)) {
									PlayerMoving data;
									data.packetType = 0x14;
									data.characterState = 0; // animation
									data.x = 1000;
									data.y = 100;
									data.x = 1000;
									data.y = 1000;
									data.punchX = 0;
									data.punchY = 0;
									data.XSpeed = 300;
									data.YSpeed = 600;
									BYTE* raw = packPlayerMoving(&data);
									memcpy(raw + 1, &var, 3);
									SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffect"), playinfo->effect));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnParticleEffectV2"), playinfo->effect));
									ENetPacket* packets = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packets);
									delete p.data;
								}
							}
							//
							((PlayerInfo*)(event.peer->data))->haveSuperSupporterName = true;
							sendState(peer);

						}
						catch (int e) {
							if (e == 1) {
								((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You have exited the world."));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
								//enet_host_flush(server);
							}
							else if (e == 2) {
								((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "You have entered bad characters in the world name!"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
								//enet_host_flush(server);
							}
							else if (e == 3) {
								((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Exit from what? Click back if you're done playing."));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
								//enet_host_flush(server);
							}
							else {
								((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "I know this menu is magical and all, but it has its limitations! You can't visit this world!"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
								//enet_host_flush(server);
							}
						}
					}
						if (id == "action")
						{

							if (act == "join_request")
							{
								isJoinReq = true;
							}
							if (act == "quit_to_exit")
							{
								sendPlayerLeave(peer, (PlayerInfo*)(event.peer->data));
								((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
								sendWorldOffers(peer);

							}
							if (act == "quit")
							{
								enet_peer_disconnect_later(peer, 0);
							}
						}
					}
					break;
			}
			case 4:
			{
				{
					BYTE* tankUpdatePacket = GetStructPointerFromTankPacket(event.packet); 
					
					if (tankUpdatePacket)
					{
						PlayerMoving* pMov = unpackPlayerMoving(tankUpdatePacket);
						if (((PlayerInfo*)(event.peer->data))->isGhost) {
							((PlayerInfo*)(event.peer->data))->isInvisible = true;
							((PlayerInfo*)(event.peer->data))->x1 = pMov->x;
							((PlayerInfo*)(event.peer->data))->y1 = pMov->y;
							pMov->x = -1000000;
							pMov->y = -1000000;
						}
						
						switch (pMov->packetType)
						{
						case 0:
							((PlayerInfo*)(event.peer->data))->x = pMov->x;
							((PlayerInfo*)(event.peer->data))->y = pMov->y;
							((PlayerInfo*)(event.peer->data))->isRotatedLeft = pMov->characterState & 0x10;
							sendPData(peer, pMov);
							if (!((PlayerInfo*)(peer->data))->joinClothesUpdated)
							{
								((PlayerInfo*)(peer->data))->joinClothesUpdated = true;
								updateAllClothes(peer);
							}
							break;

						default:
							break;
						}
						PlayerMoving *data2 = unpackPlayerMoving(tankUpdatePacket);
						//cout << data2->packetType << endl;
						if (data2->packetType == 11)
						{
							//cout << pMov->x << ";" << pMov->y << ";" << pMov->plantingTree << ";" << pMov->punchX << endl;
							//sendDrop(((PlayerInfo*)(event.peer->data))->netID, ((PlayerInfo*)(event.peer->data))->x, ((PlayerInfo*)(event.peer->data))->y, pMov->punchX, 1, 0);
							// lets take item
						}
						if (data2->packetType == 7)
						{
							//cout << pMov->x << ";" << pMov->y << ";" << pMov->plantingTree << ";" << pMov->punchX << endl;
							/*GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnRequestWorldSelectMenu"), "default|GO FOR IT\nadd_button|Showing: `wFake Worlds``|_catselect_|0.6|3529161471|\nadd_floater|Subscribe|5|0.55|3529161471\nadd_floater|Growtopia|4|0.52|4278190335\nadd_floater|Noobs|150|0.49|3529161471\nadd_floater|...|3|0.49|3529161471\nadd_floater|`6:O :O :O``|2|0.46|3529161471\nadd_floater|SEEMS TO WORK|2|0.46|3529161471\nadd_floater|?????|1|0.43|3529161471\nadd_floater|KEKEKEKEK|13|0.7|3417414143\n"));
							//for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";
							ENetPacket * packet3 = enet_packet_create(p3.data,
								p3.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet3);
							enet_host_flush(server);*/
							sendPlayerLeave(peer, (PlayerInfo*)(event.peer->data));
							sendWorldOffers(peer);
							// lets take item
						}
						if (data2->packetType == 10)
						{
							//cout << pMov->x << ";" << pMov->y << ";" << pMov->plantingTree << ";" << pMov->punchX << ";" << pMov->punchY << ";" << pMov->characterState << endl;
							ItemDefinition def;
							try {
								def = getItemDef(pMov->plantingTree);
							}
							catch (int e) {
								goto END_CLOTHSETTER_FORCE;
							}
							
							switch (def.clothType) {
							case 0:
								if (((PlayerInfo*)(event.peer->data))->cloth0 == pMov->plantingTree)
								{
									((PlayerInfo*)(event.peer->data))->cloth0 = 0;
									break;
								}
								LoadPunchEffect(peer, pMov->plantingTree);
								((PlayerInfo*)(event.peer->data))->cloth0 = pMov->plantingTree;
								break;
							case 1:
								if (((PlayerInfo*)(event.peer->data))->cloth1 == pMov->plantingTree)
								{
									((PlayerInfo*)(event.peer->data))->cloth1 = 0;
									break;
								}
								LoadPunchEffect(peer, pMov->plantingTree);
								((PlayerInfo*)(event.peer->data))->cloth1 = pMov->plantingTree;
								break;
							case 2:
								if (((PlayerInfo*)(event.peer->data))->cloth2 == pMov->plantingTree)
								{
									((PlayerInfo*)(event.peer->data))->cloth2 = 0;
									break;
								}
								LoadPunchEffect(peer, pMov->plantingTree);
								((PlayerInfo*)(event.peer->data))->cloth2 = pMov->plantingTree;
								break;
							case 3:
								if (((PlayerInfo*)(event.peer->data))->cloth3 == pMov->plantingTree)
								{
									((PlayerInfo*)(event.peer->data))->cloth3 = 0;
									break;
								}
								LoadPunchEffect(peer, pMov->plantingTree);
								((PlayerInfo*)(event.peer->data))->cloth3 = pMov->plantingTree;
								break;
							case 4:
								if (((PlayerInfo*)(event.peer->data))->cloth4 == pMov->plantingTree)
								{
									((PlayerInfo*)(event.peer->data))->cloth4 = 0;
									break;
								}
								LoadPunchEffect(peer, pMov->plantingTree);
								((PlayerInfo*)(event.peer->data))->cloth4 = pMov->plantingTree;
								break;
							case 5:
								if (pMov->plantingTree == 7912) {
									if (((PlayerInfo*)(event.peer->data))->boughtFYE == false)
									{
										GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4This item must be purchased! `6Type /Purchase"));
										ENetPacket* packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet);

										delete p.data;


										break;
										//((PlayerInfo*)(event.peer->data))->cloth0 = 0;
									}
								}
								if (pMov->plantingTree == 5480) {
									if (((PlayerInfo*)(event.peer->data))->boughtRFS == false)
									{
										GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4This item must be purchased! `6Type /Purchase"));
										ENetPacket* packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet);

										delete p.data;


										break;
										//((PlayerInfo*)(event.peer->data))->cloth0 = 0;
									}
								}
								if (pMov->plantingTree == 1204) {
									if (((PlayerInfo*)(event.peer->data))->boughtFCS == false)
									{
										GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4This item must be purchased! `6Type /Purchase"));
										ENetPacket* packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet);

										delete p.data;


										break;
										//((PlayerInfo*)(event.peer->data))->cloth0 = 0;
									}
								}
								if (pMov->plantingTree == 8286) {
									if (((PlayerInfo*)(event.peer->data))->boughtDAV == false)
									{
										GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4This item must be purchased! `6Type /Purchase"));
										ENetPacket* packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet);

										delete p.data;


										break;
										//((PlayerInfo*)(event.peer->data))->cloth0 = 0;
									}
								}
								if (pMov->plantingTree == 1876) {
									if (((PlayerInfo*)(event.peer->data))->boughtWSD == false)
									{
										GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4This item must be purchased! `6Type /Purchase"));
										ENetPacket* packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet);

										delete p.data;


										break;
										//((PlayerInfo*)(event.peer->data))->cloth0 = 0;
									}
								}
								if (pMov->plantingTree == 1874) {
									if (((PlayerInfo*)(event.peer->data))->boughtFRC == false)
									{
										GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4This item must be purchased! `6Type /Purchase"));
										ENetPacket* packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet);

										delete p.data;


										break;
										//((PlayerInfo*)(event.peer->data))->cloth0 = 0;
									}
								}
								if (pMov->plantingTree == 1986) {
									if (((PlayerInfo*)(event.peer->data))->boughtGRN == false)
									{
										GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4This item must be purchased! `6Type /Purchase"));
										ENetPacket* packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet);

										delete p.data;


										break;
										
									}
								}
								if (((PlayerInfo*)(event.peer->data))->cloth5 == pMov->plantingTree)
								{
									((PlayerInfo*)(event.peer->data))->cloth5 = 0;
									break;
								}
								LoadPunchEffect(peer, pMov->plantingTree);
								((PlayerInfo*)(event.peer->data))->cloth5 = pMov->plantingTree;
								break;
							case 6:
								if (((PlayerInfo*)(event.peer->data))->cloth6 == pMov->plantingTree)
								{
									((PlayerInfo*)(event.peer->data))->cloth6 = 0;
									((PlayerInfo*)(event.peer->data))->canDoubleJump = false;
									sendState(peer);
									break;
								}
								{
									((PlayerInfo*)(event.peer->data))->cloth6 = pMov->plantingTree;
									int item = pMov->plantingTree;
									if (item == 156 || item == 362 || item == 678 || item == 736 || item == 818 || item == 1206 || item == 1460 || item == 1550 || item == 1574 || item == 1668 || item == 1672 || item == 1674 || item == 1784 || item == 1824 || item == 1936 || item == 1938 || item == 1970 || item == 2254 || item == 2256 || item == 2258 || item == 2260 || item == 2262 || item == 2264 || item == 2390 || item == 2392 || item == 3120 || item == 3308 || item == 3512 || item == 4534 || item == 4986 || item == 5754 || item == 6144 || item == 6334 || item == 6694 || item == 6818 || item == 6842 || item == 1934 || item == 3134 || item == 6004 || item == 1780 || item == 2158 || item == 2160 || item == 2162 || item == 2164 || item == 2166 || item == 2168 || item == 2438 || item == 2538 || item == 2778 || item == 3858 || item == 350 || item == 998 || item == 1738 || item == 2642 || item == 2982 || item == 3104 || item == 3144 || item == 5738 || item == 3112 || item == 2722 || item == 3114 || item == 4970 || item == 4972 || item == 5020 || item == 6284 || item == 4184 || item == 4628 || item == 5322 || item == 4112 || item == 4114 || item == 3442 || item == 5738 || item == 5754 || item == 6004 || item == 6144 || item == 6284 || item == 6334 || item == 6694 || item == 6758 || item == 6818 || item == 6842 || item == 7084 || item == 7104 || item == 7150 || item == 7196 || item == 7204 || item == 7214 || item == 7304 || item == 7392 || item == 7412 || item == 7502 || item == 7582 || item == 7648 || item == 7676 || item == 7678 || item == 7680 || item == 7682 || item == 7734 || item == 7834 || item == 7910 || item == 7914 || item == 8024 || item == 8026 || item == 8028 || item == 8194 || item == 8286 || item == 8302 || item == 8308 || item == 8552 || item == 8582 || item == 8584 || item == 8586 || item == 8576 || item == 8578 || item == 8580 || item == 8582 || item == 8620 || item == 8862 || item == 8914 || item == 9006 || item == 5480) {
										((PlayerInfo*)(event.peer->data))->canDoubleJump = true;
									}
									else {
										((PlayerInfo*)(event.peer->data))->canDoubleJump = false;
									}
									LoadPunchEffect(peer, pMov->plantingTree);
									// ^^^^ wings
									sendState(peer);
								}
								break;
							case 7:
								if (((PlayerInfo*)(event.peer->data))->cloth7 == pMov->plantingTree)
								{
									((PlayerInfo*)(event.peer->data))->cloth7 = 0;
									break;
								}
								LoadPunchEffect(peer, pMov->plantingTree);
								((PlayerInfo*)(event.peer->data))->cloth7 = pMov->plantingTree;
								break;
							case 8:
								if (((PlayerInfo*)(event.peer->data))->cloth8 == pMov->plantingTree)
								{
									((PlayerInfo*)(event.peer->data))->cloth8 = 0;
									break;
								}
								((PlayerInfo*)(event.peer->data))->cloth8 = pMov->plantingTree;

								break;
							default:
								if (
									def.id == 7166
									|| def.id == 5078 || def.id == 5080 || def.id == 5082 || def.id == 5084
									|| def.id == 5126 || def.id == 5128 || def.id == 5130 || def.id == 5132
									|| def.id == 5144 || def.id == 5146 || def.id == 5148 || def.id == 5150
									|| def.id == 5162 || def.id == 5164 || def.id == 5166 || def.id == 5168
									|| def.id == 5180 || def.id == 5182 || def.id == 5184 || def.id == 5186
									|| def.id == 7168 || def.id == 7170 || def.id == 7172 || def.id == 7174
									) {
									if (((PlayerInfo*)(event.peer->data))->boughtAAC == false) {
										{
											GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4This item must be purchased! `6Type /Purchase"));
											ENetPacket* packet = enet_packet_create(p.data,
												p.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(peer, 0, packet);

											delete p.data;


											break;
											//((PlayerInfo*)(event.peer->data))->cloth0 = 0;
										}
									}
									if (((PlayerInfo*)(event.peer->data))->cloth_ances == pMov->plantingTree) {

										((PlayerInfo*)(event.peer->data))->cloth_ances = 0;
										break;
									}

									((PlayerInfo*)(event.peer->data))->cloth_ances = pMov->plantingTree;

								}
#ifdef TOTAL_LOG
								cout << "Invalid item activated: " << pMov->plantingTree << " by " << ((PlayerInfo*)(event.peer->data))->displayName << endl;
#endif
								break;
							}
							sendClothes(peer);
							// activate item
						END_CLOTHSETTER_FORCE:;
						}
						if (data2->packetType == 18)
						{
							sendPData(peer, pMov);
							// add talk buble
						}
						if (data2->punchX != -1 && data2->punchY != -1) {
							//cout << data2->packetType << endl;
							if (data2->packetType == 3)
							{
								using namespace std::chrono;
								if (((PlayerInfo*)(peer->data))->lastBREAK + 150 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
								{
									((PlayerInfo*)(peer->data))->lastBREAK = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
									if (((PlayerInfo*)(peer->data))->cloth_hand == 5480) {
										if (((PlayerInfo*)(event.peer->data))->isRotatedLeft = pMov->characterState & 0x10) {
											sendTileUpdate(data2->punchX, data2->punchY, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);
											sendTileUpdate(data2->punchX - 1, data2->punchY, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);
											sendTileUpdate(data2->punchX - 2, data2->punchY, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);
										}
										else {
											sendTileUpdate(data2->punchX, data2->punchY, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);
											sendTileUpdate(data2->punchX + 1, data2->punchY, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);
											sendTileUpdate(data2->punchX + 2, data2->punchY, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);
										}
									}
									else {
										sendTileUpdate(data2->punchX, data2->punchY, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);
									}
								}
								else {
								}
							}
							else {


							}
							/*PlayerMoving data;
							//data.packetType = 0x14;
							data.packetType = 0x3;
							//data.characterState = 0x924; // animation
							data.characterState = 0x0; // animation
							data.x = data2->punchX;
							data.y = data2->punchY;
							data.punchX = data2->punchX;
							data.punchY = data2->punchY;
							data.XSpeed = 0;
							data.YSpeed = 0;
							data.netID = ((PlayerInfo*)(event.peer->data))->netID;
							data.plantingTree = data2->plantingTree;
							SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
							cout << "Tile update at: " << data2->punchX << "x" << data2->punchY << endl;*/
							
						}
						delete data2;
						delete pMov;
					}

					else {
						cout << "Got bad tank packet";
					}
					/*char buffer[2048];
					for (int i = 0; i < event->packet->dataLength; i++)
					{
					sprintf(&buffer[2 * i], "%02X", event->packet->data[i]);
					}
					cout << buffer;*/
				}
			}
			break;
			case 5:
				break;
			case 6:
				//cout << GetTextPointerFromPacket(event.packet) << endl;
				break;
			}
			enet_packet_destroy(event.packet);
			break;
		}
		case ENET_EVENT_TYPE_DISCONNECT:
#ifdef TOTAL_LOG
			printf("Peer disconnected.\n");
#endif
			/* Reset the peer's client information. */
			/*ENetPeer* currentPeer;
			for (currentPeer = server->peers;
				currentPeer < &server->peers[server->peerCount];
				++currentPeer)
			{
				if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
					continue;

				GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "Player `o" + ((PlayerInfo*)(event.peer->data))->tankIDName + "`o just left the game..."));
				ENetPacket * packet = enet_packet_create(p.data,
					p.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(currentPeer, 0, packet);
				enet_host_flush(server);
			}*/
			sendPlayerLeave(peer, (PlayerInfo*)(event.peer->data));
			((PlayerInfo*)(event.peer->data))->inventory.items.clear();
			delete event.peer->data;
			event.peer->data = NULL;
		}
	}
	cout << "Program ended??? Huh?" << endl;
	while (1);
	return 0;
}

