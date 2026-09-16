rule Trojan_Win32_Emotet_RWA_MTB{
	meta:
		description = "Trojan:Win32/Emotet.RWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {81 c7 00 10 00 00 0b c7 50 56 53 6a ff } 		$a_80_1 = {51 6b 50 75 58 30 6e 36 21 54 26 67 4d 37 67 44 32 40 77 44 70 70 74 4f 4a 47 26 58 5f 4d 5f 49 42 26 3f 71 6b 29 62 26 39 53 71 32 29 7a 71 5a 50 4a 4b 68 36 63 61 24 63 4b 43 62 26 4e 2b } 	condition:
		((#a_00_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}