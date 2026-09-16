rule VirTool_Win32_Obfuscator_AQQ{
	meta:
		description = "VirTool:Win32/Obfuscator.AQQ,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {23 f6 51 56 a9 f4 ee 21 37 5e 59 53 81 f5 00 00 00 00 5b b9 ?? ?? ?? 00 a9 0a b3 50 46 7e 02 22 ed } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}