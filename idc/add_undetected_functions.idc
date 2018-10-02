// 在给定代码段搜索IDA未自动探测到的函数
// seek and add undetected functions in .text section
// by laqieer
// 2018/2/21

#include <idc.idc>
static main()
{
	auto ea, CODE_END;
	ea = 0x8000000;
	// 搜索字符串"AFJFSF\F2005/02/04(FRI) 16:55:40"作为.rodata段的开始也是.text段的结束,这个字符串根据因rom而异
	CODE_END = FindBinary(ea, SEARCH_DOWN | SEARCH_CASE, "41 46 4A 46 53 46 5C 46  32 30 30 35 2F 30 32 2F 30 34 28 46 52 49 29 20 31 36 3A 35 35 3A 34 30 00");
	Message("the end address of .text : 0x%x\n", CODE_END);
	for(ea = FindCode(ea, SEARCH_DOWN); ea != BADADDR && ea < CODE_END; ea = FindCode(ea, SEARCH_DOWN))
	{
		if(GetFunctionName(ea) == "")
		{
			if(MakeFunction(ea, BADADDR))
			{
				Message("0x%x\t%s\n", ea, GetFunctionName(ea));
				// ea = GetFunctionAttr(ea, FUNCATTR_END); // 遇到分段函数(function chunk)会循环
				ea = GetFunctionAttr(ea, FUNCATTR_END) > ea ? GetFunctionAttr(ea, FUNCATTR_END) : ea;
			}
			else
				ea = FindCode(ea, SEARCH_DOWN | SEARCH_NEXT);
		}
		else
		{
			ea = GetFunctionAttr(ea, FUNCATTR_END) > ea ? GetFunctionAttr(ea, FUNCATTR_END) : ea;
		}
		// Message("ea : 0x%x\n", ea);
	}
}