rule Trojan_Win32_Abndog_A_2{
	meta:
		description = "Trojan:Win32/Abndog.A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {85 f6 74 37 80 3e 90 75 32 80 7e 01 60 75 2c 80 7e 02 e9 75 26 8b 46 03 8d 44 30 07 8d 70 0a 56 ff d7 84 c0 74 15 80 3e 74 75 10 6a 01 8d 45 ec 50 56 } 		$a_01_1 = {81 c7 e9 1c 00 00 57 ff d6 84 c0 74 14 80 3f 75 75 0f 6a 01 8d 85 fc fd ff ff 50 57 e8 } 		$a_00_2 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 4e 00 42 00 41 00 5f 00 53 00 4f 00 46 00 54 00 } 		$a_00_3 = {4d 6d 49 73 41 64 64 72 65 73 73 56 61 6c 69 64 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=12
 
}