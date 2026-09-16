rule TrojanSpy_Win32_Ursnif__Ursnif{
	meta:
		description = "TrojanSpy:Win32/Ursnif!!Ursnif.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_00_0 = {73 6f 66 74 3d 25 75 26 76 65 72 73 69 6f 6e 3d 25 75 26 75 73 65 72 3d 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 26 73 65 72 76 65 72 3d 25 75 26 69 64 3d 25 75 26 63 72 63 3d 25 78 } 		$a_00_1 = {40 53 4f 43 4b 53 3d 2a 40 } 		$a_00_2 = {54 6f 72 43 6c 69 65 6e 74 } 		$a_00_3 = {54 6f 72 43 72 63 } 		$a_00_4 = {2e 6f 6e 69 6f 6e 2f } 	condition:
		((#a_00_0  & 1)*3+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=7
 
}