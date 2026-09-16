rule Trojan_Win32_LokiBot_DL_MTB_2{
	meta:
		description = "Trojan:Win32/LokiBot.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b c2 03 c3 90 05 05 01 90 c6 [0-04] 90 05 05 01 90 43 81 fb [0-04] 75 ec } 		$a_02_1 = {33 c0 89 45 [0-04] 33 c9 90 05 05 01 90 8b c1 90 05 10 01 90 8a 90 90 [0-04] 90 05 10 01 90 80 f2 e3 90 05 10 01 90 8b c6 03 c1 90 05 10 01 90 89 45 fc 90 05 10 01 90 88 55 fb 90 05 10 01 90 8b 55 fc 90 05 10 01 90 8a 45 fb 90 05 10 01 90 88 02 90 05 05 01 90 41 81 f9 ?? ?? ?? ?? 75 bf } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}