rule Trojan_Win32_Glupteba_RPY_MTB_4{
	meta:
		description = "Trojan:Win32/Glupteba.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 c7 33 c1 2b f0 89 44 24 10 8b c6 c1 e0 04 } 		$a_01_1 = {89 44 24 10 8b 44 24 24 01 44 24 10 03 de 31 5c 24 0c 8b 44 24 10 31 44 24 0c 8b 44 24 0c 29 44 24 14 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}