rule Trojan_Win32_LummaStealer_NL_MTB_5{
	meta:
		description = "Trojan:Win32/LummaStealer.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {89 13 8d 05 a0 3a 14 03 89 10 89 42 18 e8 55 14 00 00 fc e8 6f b9 fd ff 8b 44 24 78 89 04 24 8b 44 24 7c 89 44 24 04 } 		$a_01_1 = {8b 7c 24 04 8b 15 b4 3a 18 03 64 8b 12 8b 02 8b 1c 24 89 58 20 8d 5c 24 } 		$a_01_2 = {70 61 79 6c 6f 61 64 54 79 70 65 } 		$a_01_3 = {4c 41 55 4e 43 48 5f 53 54 41 47 45 5f 55 4e 53 50 45 43 49 46 49 45 44 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}