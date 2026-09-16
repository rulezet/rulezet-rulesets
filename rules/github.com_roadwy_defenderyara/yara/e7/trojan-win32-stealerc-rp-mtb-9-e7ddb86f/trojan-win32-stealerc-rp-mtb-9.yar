rule Trojan_Win32_Stealerc_RP_MTB_9{
	meta:
		description = "Trojan:Win32/Stealerc.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 67 61 73 79 75 64 67 75 79 67 69 75 78 48 49 41 } 		$a_01_1 = {58 63 50 55 43 58 6c 58 6b 52 6e 79 41 64 51 } 		$a_01_2 = {5a 74 72 62 6f 62 44 66 52 56 44 56 53 59 4a 44 62 69 54 6a 4a 59 4d 74 6e 41 70 6d 7a 6e 5a 49 49 47 6d } 		$a_01_3 = {64 59 75 56 58 7a 6b 4c 4c 56 57 62 63 78 70 4e 6b 7a 77 4d 51 4e 79 63 77 46 72 4d 53 68 7a 4a 44 64 77 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}