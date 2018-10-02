// 从IDA数据库生成gbadisasm需要的配置文件. Export configuration file for gbadisasm from IDA database.
// by laqieer
// 2018/2/20

#include <idc.idc>

static main() {
	// auto cfg, cfgName, addr, cmt, isARM, name, armBoundary;	
	auto cfg, cfgName, addr, cmt, isThumb, name;
	// armBoundary = LocByName("AgbMain");
	cfgName = AskFile(1, "*.cfg", "export to");
	cfg = fopen(cfgName, "w");
	if(!cfg)
	{
		Warning("Error when opening %s", cfgName);
		return;
	}
	addr = 0;
	for(addr = NextFunction(addr); addr != BADADDR; addr = NextFunction(addr))
	{
		name = Name(addr);
		// isARM = (FindCode(addr, SEARCH_DOWN | SEARCH_NEXT) - addr -2) / 2;	// 可能出现误判，因为thumb函数里也会出现第一条指令距离下一个指令超过2字节的情形例如跳转语句或者伪指令(例如movs r1,#0x04000000, 其实是由2条指令构成的)，或者整个函数就一条"bx lr"指令(空函数)
		// isARM = addr < armBoundary ? 1 : 0; // 假定AgbMain是第一个thumb函数
		isThumb = GetReg(addr, "T");	// 取虚拟寄存器T的值来区分arm代码和thumb代码
		cmt = GetFunctionCmt(addr, 1);
		// if(cmt)
			//fprintf(cfg, "# %s\n", cmt);	// 只允许单行注释，写入配置文件的多行注释从第二行开始开头会缺少#
		if(cmt != "" && strstr(cmt, "\n") > 0)
			fprintf(cfg, "# %s\n", substr(cmt, 0, strstr(cmt, "\n")));	// 多行注释只输出第一行注释
		// writestr(cfg, isARM? "arm_func": "thumb_func");
		writestr(cfg, isThumb? "thumb_func": "arm_func");
		fprintf(cfg, " 0x%x %s\n", addr, name);
	}
	fclose(cfg);
}