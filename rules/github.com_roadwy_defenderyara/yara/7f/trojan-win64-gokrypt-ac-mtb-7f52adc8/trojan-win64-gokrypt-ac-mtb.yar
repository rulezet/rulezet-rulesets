rule Trojan_Win64_GoKrypt_AC_MTB{
	meta:
		description = "Trojan:Win64/GoKrypt.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } 		$a_01_1 = {54 63 79 41 6b 71 68 34 6f 4a 58 67 56 33 57 59 79 4c 34 4b 45 66 43 4d 6b 39 57 38 6f 4a 43 70 6d 78 31 62 6f 2b 6a 56 67 4b 59 3d } 		$a_01_2 = {55 44 52 62 6f 74 54 4f 4d 74 6b 75 66 37 54 54 4a 51 50 69 53 56 6a 64 52 5a 71 55 6d 69 31 6f 47 65 35 66 55 73 32 68 4c 77 77 3d } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}