rule Trojan_Win32_Dialer_SGB_MTB{
	meta:
		description = "Trojan:Win32/Dialer.SGB!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 6a 75 6d 70 2e 70 68 70 33 } 		$a_01_1 = {75 67 68 20 73 70 61 } 		$a_01_2 = {74 73 72 5f 6d 65 64 69 61 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}