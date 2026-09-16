rule Trojan_Win32_Fareit_DEL_MTB_3{
	meta:
		description = "Trojan:Win32/Fareit.DEL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {59 6c 63 46 33 6e 6b 4f 4a 4f 4b 51 38 38 53 4a 73 55 61 7a 42 50 76 45 6d 72 52 49 52 30 44 35 74 57 42 64 6b 54 } 		$a_81_1 = {4e 74 63 31 62 63 6c 61 50 65 41 46 71 6e 58 39 63 75 48 } 		$a_81_2 = {6f 43 32 6a 32 45 59 4c 35 78 57 61 51 7a 76 6a } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}