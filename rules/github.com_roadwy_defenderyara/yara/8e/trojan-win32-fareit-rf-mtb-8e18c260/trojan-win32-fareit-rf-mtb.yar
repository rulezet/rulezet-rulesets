rule Trojan_Win32_Fareit_RF_MTB{
	meta:
		description = "Trojan:Win32/Fareit.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {49 f2 ed c5 30 4f 92 30 62 5d 13 e0 17 f2 8d dd 77 a5 } 		$a_01_1 = {49 00 73 00 63 00 6f 00 62 00 61 00 71 00 75 00 65 00 62 00 75 00 2e 00 65 00 78 00 65 00 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}