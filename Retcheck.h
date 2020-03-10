#pragma once
#include <Windows.h>
#include <vector>
/*
The code used in this bypass is made by Dark Exploit/Ares
It was inspired obviously with etrnals method of copying the functions memory to an unhashed section.
It uses: My OpCode Scanner(Which features alternating opcodes and lengths) and My Memory Functions
If you wanna join a discord where a lot of devs are in you will need to DM me on discord as I don't wanna another warning from advertising XD
My Discord Name: Ares#8183
*/
namespace OpCodeScanner
{
	struct cOpCode
	{
		byte OpCode = 0;
		byte Length = 0;
		byte MinLength = 0;
		byte MaxLength = 0;
	};
	std::vector<DWORD> Scan(std::vector<cOpCode> Identifiers, DWORD Start, DWORD End)
	{
		std::vector<DWORD> Found;
		//printf("Scanning: %x\nSize: %x\nEnd: %x\n", noaslr(Start), (End - Start), noaslr(End));
		for (int i = 0; i < (End - Start); i++)
		{
			DWORD Current = Start + i;
			bool Foundb = false;
			//printf("New\n");
			for (int o = 0; o < Identifiers.size(); o++)
			{
				byte Size = 0;
				//if (o > 1)
				//printf("Current Op: %x Wanted: %x\n", *(byte*)Current, Identifiers[o].OpCode);
				if (Identifiers[o].OpCode == *(byte*)Current)
				{
					if (o == Identifiers.size() - 1)
					{
						Foundb = true;
						break;
					}
				}
				else if (Identifiers[o].OpCode != 0)
				{
					break;
				}
				if (Identifiers[o].Length == 0)
				{
					for (int p = Identifiers[o].MinLength; p < Identifiers[o].MaxLength + 1; p++)
					{
						//if (o > 1)
						//printf("Next Op at guess %d: %x Wanted: %x\n", p, *(byte*)(Current + p), Identifiers[o + 1].OpCode);
						if (*(byte*)(Current + p) == Identifiers[o + 1].OpCode)
						{
							Size = p;
							break;
						}
					}
					if (Size == 0)
						break;
				}
				else
				{
					//if (o > 1)
					//printf("Next Op: %x Wanted: %x\n", *(byte*)(Current + Identifiers[o].Length), Identifiers[o + 1].OpCode);
					if (Identifiers[o + 1].OpCode != 0)
					{
						if (*(byte*)(Current + Identifiers[o].Length) == Identifiers[o + 1].OpCode)
							Size = Identifiers[o].Length;
						else
							break;
					}
					else
					{
						Size = Identifiers[o].Length;
					}
				}
				//if (o > 1)
				//printf("Size: %d\n", Size);
				Current += Size;
			}
			if (Foundb)
				Found.push_back(Start + i);
		}
		return Found;
	}
}

template <typename T>
inline T& GetAddr(DWORD Address)
{
	return *(T*)Address;
}

bool IsPrologue(DWORD Address)
{
	BYTE* b = (BYTE*)Address;
	if (b[0] == 0x55 && b[1] == 0x8B && b[2] == 0xEC)
	{
		return true;
	}
	else if (b[0] == 0x53 && b[1] == 0x8B && b[2] == 0xDC)
	{
		return true;
	}
	else if (b[0] == 0x56 && b[1] == 0x8B && b[2] == 0xF1)
	{

		for (DWORD i = 0; i < 0xFF; i++) {
			DWORD Current = (Address + i);
			if (*(BYTE*)Current == 0x5E && (*(BYTE*)(Current + 1) == 0xC3 || *(BYTE*)(Current + 1) == 0xC2)) {
				return true;
			}
		}

		return false;
	}
	else
	{
		return false;
	}
}

DWORD FindNextPrologue(DWORD Address)
{
	DWORD Location = Address;
	bool Prologue = false;
	do
	{
		Location += 0x10;
		Prologue = IsPrologue(Location);
		if (Location > 0x0168D000)
			return 0;
	} while (!Prologue);
	return Location;
}

DWORD CloneFunction(DWORD addr, DWORD End)
{
	DWORD Function;
	if (addr == 0)
		return addr;
	DWORD funcSz = End - addr;//Function Size
	PVOID nFunc = nFunc = VirtualAlloc(NULL, funcSz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);//Allocate Memory Inside Of Roblox
	if (nFunc == NULL) {
		return addr;
	}
	memcpy(nFunc, (void*)addr, funcSz);//Clone Function To New Un-Hashed Location
	Function = (DWORD)nFunc;
	DWORD cNFunc = (DWORD)nFunc;
	do {
		if (GetAddr<byte>(cNFunc) == 0xE8)
		{
			DWORD tFunc = addr + (cNFunc - (DWORD)nFunc);
			DWORD oFunc = (tFunc + *(DWORD*)(tFunc + 1)) + 5;

			if (IsPrologue(oFunc))
			{
				DWORD realCAddr = oFunc - cNFunc - 5;
				GetAddr<DWORD>(cNFunc + 1) = realCAddr;
			}
			cNFunc += 5;
		}
		else
			cNFunc += 1;
	} while (cNFunc < (DWORD)nFunc + funcSz);
	return Function;
}

std::vector<OpCodeScanner::cOpCode> RetCheckOpCodesDefault
{
{0x3B, 6},
{0, 0, 2, 6},
{0xA1, 5},
{0x8B, 3},
{0x2B, 2},
{0x3B, 6},
{0x72, 2},
{0xA1, 5},
{0x81, 10},
{0x81, 10},
{0xA3, 5},
{0xA1, 5},
};

std::vector<OpCodeScanner::cOpCode> RetCheckOpCodesSecondary
{
{0x3B, 6},
{0, 0, 2, 6},
{0xA1, 5},
{0x8B, 3},
{0x2B, 2},
{0x8B, 2},
{0x3B, 6},
{0, 0, 2, 6},
{0x8B, 6},
{0x81, 10},
{0x81, 10},
{0x89, 6},
{0x8B, 6},
};

/*
This function will clone any specified Lua C addresses and move them to an unhashed location in Roblox.
Next it will remove the retcheck inside of the function.
*/
DWORD RetCheckBypass(DWORD addr)
{
	DWORD Next = FindNextPrologue(addr);
	std::vector<DWORD> Found1 = OpCodeScanner::Scan(RetCheckOpCodesDefault, addr, (addr + (Next - addr)));
	std::vector<DWORD> Found2 = OpCodeScanner::Scan(RetCheckOpCodesSecondary, addr, (addr + (Next - addr)));
	Found1.insert(Found1.end(), Found2.begin(), Found2.end());
	if (Found1.size() == 0)
		return addr;
	for (int i = 0; i < Found1.size(); i++)
		Found1[i] = Found1[i] - addr;
	DWORD nFunc = CloneFunction(addr, Next);
	for (int i = 0; i < Found1.size(); i++)
	{
		if (GetAddr<byte>(nFunc + Found1[i] + 6) == 0x72)
			GetAddr<byte>(nFunc + Found1[i] + 6) = 0xEB;
		else
			GetAddr<byte>(nFunc + Found1[i] + 7) = 0x83;
	}
	return nFunc;
}