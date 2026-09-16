rule Trojan_Win32_Fareit_VB_MTB_4{
	meta:
		description = "Trojan:Win32/Fareit.VB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } 		$a_01_1 = {52 00 4b 00 75 00 75 00 71 00 49 00 4c 00 6d 00 31 00 7a 00 41 00 33 00 4a 00 6a 00 57 00 70 00 41 00 63 00 63 00 61 00 30 00 68 00 63 00 44 00 74 00 70 00 76 00 53 00 77 00 68 00 36 00 4d 00 32 00 30 00 35 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}