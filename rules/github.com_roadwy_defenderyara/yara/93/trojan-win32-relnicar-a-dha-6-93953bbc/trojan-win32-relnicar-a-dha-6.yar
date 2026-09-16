rule Trojan_Win32_Relnicar_A_dha_6{
	meta:
		description = "Trojan:Win32/Relnicar.A!dha!!Relnicar.gen!C,SIGNATURE_TYPE_ARHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 00 77 00 73 00 63 00 2e 00 69 00 63 00 6f 00 2e 00 54 00 4d 00 50 00 } 		$a_00_1 = {5c 00 52 00 45 00 4d 00 4f 00 56 00 45 00 44 00 49 00 53 00 4b 00 5c 00 } 		$a_00_2 = {73 65 73 73 69 6f 6e 74 68 3d 25 64 3b 20 75 69 64 74 68 3d 25 64 3b 20 63 6f 64 65 74 68 3d 25 64 3b 20 73 69 7a 65 74 68 3d 25 64 3b 20 6c 65 6e 67 74 68 3d 25 64 3b } 	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10) >=30
 
}