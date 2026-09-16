rule TrojanDropper_WinNT_Adwind_BD_MTB{
	meta:
		description = "TrojanDropper:WinNT/Adwind.BD!MTB,SIGNATURE_TYPE_JAVAHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {62 68 6d 76 70 78 62 64 79 65 2f 4d 63 76 7a 67 64 75 77 7a 76 7a } 		$a_00_1 = {72 65 73 6f 75 72 63 65 73 2f 6d 6e 76 6e 74 67 73 65 6b 75 } 		$a_00_2 = {7a 6d 7a 75 6b 72 62 68 65 6b 2e 6a 73 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}