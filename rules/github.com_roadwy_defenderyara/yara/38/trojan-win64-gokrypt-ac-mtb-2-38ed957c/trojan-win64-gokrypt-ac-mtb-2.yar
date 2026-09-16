rule Trojan_Win64_GoKrypt_AC_MTB_2{
	meta:
		description = "Trojan:Win64/GoKrypt.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 89 e7 fc f3 48 a5 48 89 e6 48 8b 0e 48 8b 56 08 4c 8b 46 10 4c 8b 4e 18 66 48 0f 6e c1 66 48 0f 6e ca 66 49 0f 6e d0 66 49 0f 6e d9 ff d0 } 		$a_01_1 = {47 6f 20 62 75 69 6c 64 69 6e 66 3a } 		$a_01_2 = {32 35 38 45 41 46 41 35 2d 45 39 31 34 2d 34 37 44 41 2d 39 35 43 41 2d 43 35 41 42 30 44 43 38 35 42 31 31 } 		$a_01_3 = {48 6a 4d 57 5a 34 79 36 6b 43 2e 6b 4c 79 6a 41 49 58 6b 59 61 39 6b } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}