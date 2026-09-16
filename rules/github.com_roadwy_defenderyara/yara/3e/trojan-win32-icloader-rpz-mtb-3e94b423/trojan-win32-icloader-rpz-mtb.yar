rule Trojan_Win32_ICLoader_RPZ_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {86 5b fd cc 5a f5 d6 42 08 41 84 27 a3 72 f7 20 92 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}