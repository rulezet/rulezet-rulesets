rule Trojan_Win32_Guloader_RPO_MTB_3{
	meta:
		description = "Trojan:Win32/Guloader.RPO!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {ff d2 66 0f d8 c4 0f 69 cd d9 e1 eb 19 } 		$a_01_1 = {09 14 08 66 0f 74 f8 66 0f eb ea d9 c9 d8 d7 eb 13 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}