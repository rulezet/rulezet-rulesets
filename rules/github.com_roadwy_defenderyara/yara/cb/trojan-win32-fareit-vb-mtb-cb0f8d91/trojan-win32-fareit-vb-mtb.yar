rule Trojan_Win32_Fareit_VB_MTB{
	meta:
		description = "Trojan:Win32/Fareit.VB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } 		$a_01_1 = {55 00 63 00 6b 00 39 00 75 00 4e 00 50 00 30 00 36 00 7a 00 4f 00 70 00 38 00 34 00 58 00 6c 00 72 00 37 00 31 00 44 00 31 00 31 00 33 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}