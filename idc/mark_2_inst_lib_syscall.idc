// 标注仅含2条指令的agb系统调用封装函数
// by laqieer
// 2018/2/10

#include <idc.idc>

static main() {
	auto addr, funcNameTable;
	
	funcNameTable = GetArrayId("SVC Table");
	if(funcNameTable == -1)
	{
		funcNameTable = CreateArray("SVC Table");
		SetArrayString(funcNameTable, 0, "SoftReset");
		SetArrayString(funcNameTable, 1, "RegisterRamReset");
		SetArrayString(funcNameTable, 2, "Halt");
		SetArrayString(funcNameTable, 3, "Stop");
		SetArrayString(funcNameTable, 4, "IntrWait");
		SetArrayString(funcNameTable, 5, "VBlankIntrWait");
		SetArrayString(funcNameTable, 6, "Div");
		SetArrayString(funcNameTable, 7, "DivArm");
		SetArrayString(funcNameTable, 8, "Sqrt");
		SetArrayString(funcNameTable, 9, "ArcTan");
		SetArrayString(funcNameTable, 0xA, "ArcTan2");
		SetArrayString(funcNameTable, 0xB, "CpuSet");
		SetArrayString(funcNameTable, 0xC, "CpuFastSet");
		SetArrayString(funcNameTable, 0xD, "GetBiosChecksum");
		SetArrayString(funcNameTable, 0xE, "BgAffineSet");
		SetArrayString(funcNameTable, 0xF, "ObjAffineSet");
		SetArrayString(funcNameTable, 0x10, "BitUnPack");
		SetArrayString(funcNameTable, 0x11, "LZ77UnCompWram");
		SetArrayString(funcNameTable, 0x12, "LZ77UnCompVram");
		SetArrayString(funcNameTable, 0x13, "HuffUnComp");
		SetArrayString(funcNameTable, 0x14, "RLUnCompWram");
		SetArrayString(funcNameTable, 0x15, "RLUnCompVram");
		SetArrayString(funcNameTable, 0x16, "Diff8bitUnFilterWram");
		SetArrayString(funcNameTable, 0x17, "Diff8bitUnFilterVram");
		SetArrayString(funcNameTable, 0x18, "Diff16bitUnFilter");
		SetArrayString(funcNameTable, 0x19, "SoundBias");
		SetArrayString(funcNameTable, 0x1A, "SoundDriverInit");
		SetArrayString(funcNameTable, 0x1B, "SoundDriverMode");
		SetArrayString(funcNameTable, 0x1C, "SoundDriverMain");
		SetArrayString(funcNameTable, 0x1D, "SoundDriverVSync");
		SetArrayString(funcNameTable, 0x1E, "SoundChannelClear");
		SetArrayString(funcNameTable, 0x1F, "MidiKey2Freq");
		SetArrayString(funcNameTable, 0x20, "SoundWhatever0");
		SetArrayString(funcNameTable, 0x21, "SoundWhatever1");
		SetArrayString(funcNameTable, 0x22, "SoundWhatever2");
		SetArrayString(funcNameTable, 0x23, "SoundWhatever3");
		SetArrayString(funcNameTable, 0x24, "SoundWhatever4");
		SetArrayString(funcNameTable, 0x25, "MultiBoot");
		SetArrayString(funcNameTable, 0x26, "HardReset");
		SetArrayString(funcNameTable, 0x27, "CustomHalt");
		SetArrayString(funcNameTable, 0x28, "SoundDriverVSyncOff");
		SetArrayString(funcNameTable, 0x29, "SoundDriverVSyncOn");
		SetArrayString(funcNameTable, 0x2A, "SoundGetJumpList");
	}
	
	addr = 0x8000000;
	//while(addr < 0x9000000 && addr != BADADDR)
	while(1)
	{
		addr = FindBinary(addr, SEARCH_DOWN | SEARCH_CASE | SEARCH_NOSHOW, "DF 70 47");
		if(addr >= 0x9000000 || addr == BADADDR)
			break;
		addr = addr - 1;
		print(addr);
		//addr = addr & 0x9fffffe;
		//if(GetFunctionAttr(addr, FUNCATTR_END) - GetFunctionAttr(addr, FUNCATTR_START) == 4)
		//if(isCode(addr) && GetFunctionAttr(addr, FUNCATTR_START) == addr && Byte(addr) < 0x2B)
		//if(GetFunctionAttr(addr, FUNCATTR_START) == addr && Byte(addr) < 0x2B)
		if(GetFunctionAttr(addr, FUNCATTR_START) == addr && GetFunctionAttr(addr, FUNCATTR_END) == addr + 4 && Byte(addr) < 0x2B)
		{
			MakeNameEx(addr, GetArrayElement(AR_STR, funcNameTable, Byte(addr)), SN_NOCHECK);
			SetFunctionFlags(addr, FUNC_LIB);
			print(GetFunctionName(addr));
		}
		addr = addr + 4;
	}
}