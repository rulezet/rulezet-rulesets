rule Trojan_BAT_Stealer_ARA_MTB{
	meta:
		description = "Trojan:BAT/Stealer.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {62 68 63 77 79 6a 68 77 77 36 63 73 39 67 7a 6a 6a 6a 63 76 79 75 70 6c 67 70 34 70 61 38 74 6c } 		$a_01_1 = {4d 61 72 6b 64 69 67 2e 52 65 73 6f 6c 76 65 72 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}