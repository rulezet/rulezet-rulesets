rule Trojan_Win32_Emotet_RWA_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.RWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {78 4b 54 53 4e 23 5e 43 4b 45 6f 6a 3e 39 74 62 23 31 3c 2a 4d 57 54 73 76 36 33 34 6b 35 62 54 52 43 37 23 65 35 29 4e 6a 4f 58 75 36 46 43 66 77 6c 40 4a 42 4c 70 54 30 3e 56 4a 78 3c 79 50 55 73 41 30 4b 7a 4e 7a 45 6f 39 30 63 25 6b 54 26 47 34 41 23 4d 53 34 26 } 		$a_03_1 = {0d 00 10 00 00 [0-05] 8b 55 [0-05] 6a 00 6a ff ff [0-05] 89 } 	condition:
		((#a_80_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}