rule Trojan_Win32_Sabsik_RF_MTB{
	meta:
		description = "Trojan:Win32/Sabsik.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {62 6a 58 56 5a 67 72 4d 55 39 51 47 50 73 71 63 67 32 4a 47 64 43 61 4f 43 4b } 		$a_81_1 = {6e 76 52 41 64 33 63 6b 72 32 77 79 73 53 57 32 64 32 57 67 61 66 65 72 72 66 75 31 69 63 } 		$a_81_2 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}