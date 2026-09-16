rule Trojan_BAT_KillMBR_ARAS_MTB_2{
	meta:
		description = "Trojan:BAT/KillMBR.ARAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 54 4f 44 20 54 72 6f 6a 61 6e 20 63 6c 61 73 73 5c 54 4f 44 5c 54 4f 44 5c 6f 62 6a 5c 44 65 62 75 67 5c 54 4f 44 2e 70 64 62 } 		$a_01_1 = {72 65 67 5f 64 65 73 74 72 6f 79 } 		$a_01_2 = {6d 62 72 5f 64 65 73 74 72 6f 79 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}