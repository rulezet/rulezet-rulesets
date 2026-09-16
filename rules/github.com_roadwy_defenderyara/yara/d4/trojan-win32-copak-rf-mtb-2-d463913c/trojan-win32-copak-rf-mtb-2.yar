rule Trojan_Win32_Copak_RF_MTB_2{
	meta:
		description = "Trojan:Win32/Copak.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {96 87 a7 00 [0-15] 8a 89 a7 00 [0-40] 31 [0-35] ac 89 a7 00 0f 8c ?? ff ff ff } 		$a_01_1 = {68 74 6f 4d 76 4c 41 61 } 		$a_01_2 = {5a 7a 4b 48 49 45 6f 4d 67 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}