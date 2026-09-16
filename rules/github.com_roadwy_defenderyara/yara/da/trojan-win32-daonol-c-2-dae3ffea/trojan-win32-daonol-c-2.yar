rule Trojan_Win32_Daonol_C_2{
	meta:
		description = "Trojan:Win32/Daonol.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 6e 74 69 4d 63 48 54 4e 4f 44 33 4c 49 56 45 50 61 6e 64 3c 55 41 20 43 4f 4d 4f 45 53 53 20 43 41 55 70 6c 69 76 65 4e 6f 72 74 53 70 79 53 45 6e 69 67 41 56 50 55 54 4d 55 46 41 64 6f 62 53 55 50 45 } 		$a_00_1 = {31 c9 83 c7 08 57 51 51 b5 80 51 6a 00 55 89 e8 8b 4b 54 8d 7e fb ff d7 } 		$a_00_2 = {03 5b 3c 8b 7b 50 57 47 c1 e6 10 6a 40 99 b6 30 52 57 56 ff d5 } 	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}