rule Trojan_Win32_Opcast_SK_MTB{
	meta:
		description = "Trojan:Win32/Opcast.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {75 7a 78 68 6e 75 63 73 73 62 64 7a } 		$a_81_1 = {59 30 55 32 55 38 41 34 } 		$a_81_2 = {61 4e 5a 30 67 32 42 35 50 32 65 35 68 32 48 33 56 37 6f } 		$a_81_3 = {70 57 68 36 47 30 55 36 6f 31 4e 37 71 30 67 31 44 31 51 48 64 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}