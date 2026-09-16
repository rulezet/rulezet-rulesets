rule Trojan_Win32_ClipBanker_RA_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {6d 61 72 69 65 5c 44 65 73 6b 74 6f 70 5c 63 6c 69 70 6d 6f 6e 69 74 6f 72 20 4b 45 54 48 41 53 20 46 49 4e 41 4c 20 45 56 45 52 59 54 48 49 4e 47 20 46 49 58 45 44 5c 63 6c 69 70 6d 6f 6e 69 74 6f 72 } 		$a_01_1 = {43 4c 49 50 42 4f 41 52 44 3a 20 27 27 20 76 73 2e 20 27 27 } 	condition:
		((#a_81_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}