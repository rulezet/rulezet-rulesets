rule Trojan_Win32_Relnicar_A_dha_4{
	meta:
		description = "Trojan:Win32/Relnicar.A!dha!!Relnicar.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 69 64 3a 25 73 0d 0a 55 73 65 72 3a 25 73 0d 0a 43 6f 6d 70 75 74 65 72 3a 25 73 } 		$a_00_1 = {4c 61 6e 20 69 70 3a 25 73 0d 0a 55 72 6c 31 3a 25 73 20 } 		$a_00_2 = {65 78 70 61 6e 64 2e 65 78 65 20 2d 46 3a 2a 20 22 25 73 22 } 	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10) >=30
 
}