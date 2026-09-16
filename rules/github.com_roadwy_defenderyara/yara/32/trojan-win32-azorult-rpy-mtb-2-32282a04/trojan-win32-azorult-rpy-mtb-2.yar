rule Trojan_Win32_Azorult_RPY_MTB_2{
	meta:
		description = "Trojan:Win32/Azorult.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {56 8b 30 8b 40 04 89 45 f8 8b 45 0c 8b 08 89 4d e0 8b 48 04 89 4d e8 8b 48 08 8b 40 0c 57 } 		$a_01_1 = {8b 45 08 89 78 04 5f 89 30 5e 5b c9 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}