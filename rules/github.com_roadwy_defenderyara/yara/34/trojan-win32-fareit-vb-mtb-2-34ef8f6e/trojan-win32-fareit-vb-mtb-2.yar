rule Trojan_Win32_Fareit_VB_MTB_2{
	meta:
		description = "Trojan:Win32/Fareit.VB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } 		$a_01_1 = {5a 00 4a 00 53 00 45 00 70 00 52 00 78 00 54 00 68 00 4b 00 46 00 6d 00 46 00 71 00 6a 00 44 00 71 00 4a 00 5a 00 34 00 30 00 79 00 38 00 35 00 4c 00 37 00 34 00 32 00 31 00 31 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}