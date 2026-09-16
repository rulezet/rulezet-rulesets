rule Trojan_Win32_Emotet_DH_2{
	meta:
		description = "Trojan:Win32/Emotet.DH,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {65 72 68 65 72 6a 23 40 21 67 62 65 72 68 2e 70 64 62 } 		$a_01_1 = {7a 71 37 7a 77 65 67 61 5f 6a 66 2e 70 64 62 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}