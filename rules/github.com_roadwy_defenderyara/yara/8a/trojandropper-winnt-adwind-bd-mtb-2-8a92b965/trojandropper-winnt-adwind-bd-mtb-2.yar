rule TrojanDropper_WinNT_Adwind_BD_MTB_2{
	meta:
		description = "TrojanDropper:WinNT/Adwind.BD!MTB,SIGNATURE_TYPE_JAVAHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {6d 69 74 62 61 64 6b 77 61 64 2f 4d 6f 71 7a 68 62 6c 71 77 6d 78 } 		$a_00_1 = {6c 77 68 75 6e 6a 67 66 64 78 2e 6a 73 } 		$a_00_2 = {72 65 73 6f 75 72 63 65 73 2f 63 7a 74 64 73 7a 64 65 7a 78 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}