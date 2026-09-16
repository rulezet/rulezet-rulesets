rule Trojan_BAT_Beyuwa_A{
	meta:
		description = "Trojan:BAT/Beyuwa.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6b 31 00 6b 32 00 6b 33 } 		$a_01_1 = {42 79 65 00 52 75 6e 41 77 61 79 00 57 68 79 } 		$a_01_2 = {62 31 00 62 32 00 62 33 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}