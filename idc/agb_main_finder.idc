// 自动查找并调至AgbMain()
// by laqieer
// 2018/2/10

#include <idc.idc>

static main() {
	auto startVectorAddr, loopAddrInStartVector, interMainBegin, interMainEnd, agbMainBegin;
	startVectorAddr = LocByName("start_vector");
	if(startVectorAddr == BADADDR)
	{
		startVectorAddr = 0x080000C0;
		MakeNameEx(startVectorAddr, "start_vector", SN_NOCHECK);
	}
	loopAddrInStartVector = FindText(startVectorAddr, SEARCH_DOWN | SEARCH_REGEX | SEARCH_NOSHOW, 0, 0, "B +start\_vector");
	MakeFunction(startVectorAddr, loopAddrInStartVector + 4);
	SetFunctionFlags(startVectorAddr, FUNC_NORET);
	MakeNameEx(loopAddrInStartVector + 4, "sp_usr", SN_NOCHECK);
	MakeNameEx(loopAddrInStartVector + 8, "sp_irq", SN_NOCHECK);
	MakeNameEx(0x03007FFC, "INTR_VECTOR_BUF", SN_NOCHECK);
	MakeDword(0x03007FFC);
	interMainBegin = Dfirst(FindText(startVectorAddr, SEARCH_DOWN | SEARCH_NOSHOW, 0, 0, "INTR_VECTOR_BUF") + 4);
	interMainEnd = FindText(interMainBegin, SEARCH_DOWN | SEARCH_NOSHOW, 0, 0, ".long INTR_VECTOR_BUF");
	MakeNameEx(interMainBegin, "intr_main", SN_NOCHECK);
	MakeFunction(interMainBegin, interMainEnd);
	agbMainBegin = Dnext(loopAddrInStartVector - 4 * 3, Dfirst(loopAddrInStartVector - 4 * 3)) & 0x09fffffe;
	MakeNameEx(agbMainBegin, "AgbMain", SN_NOCHECK);
	MakeFunction(agbMainBegin, BADADDR);
	SetFunctionFlags(agbMainBegin, FUNC_NORET);
	Jump(agbMainBegin);
}