rule Trojan_Win32_Injector_MA_MTB{
	meta:
		description = "Trojan:Win32/Injector.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4d f8 83 c1 01 89 4d f8 8b 55 f8 3b 55 e8 0f 83 ?? ?? ?? ?? 8b 45 f4 03 45 f8 8a 08 88 4d ff } 		$a_01_1 = {4c 6f 61 64 65 72 2e 70 64 62 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}