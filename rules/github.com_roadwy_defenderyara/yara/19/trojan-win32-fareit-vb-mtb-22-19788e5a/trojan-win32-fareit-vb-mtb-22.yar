rule Trojan_Win32_Fareit_VB_MTB_22{
	meta:
		description = "Trojan:Win32/Fareit.VB!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } 		$a_01_1 = {50 00 55 00 4c 00 78 00 39 00 4a 00 39 00 39 00 65 00 50 00 30 00 6a 00 52 00 56 00 33 00 70 00 37 00 4f 00 4a 00 48 00 78 00 56 00 72 00 76 00 75 00 67 00 37 00 44 00 4e 00 6d 00 56 00 32 00 31 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}