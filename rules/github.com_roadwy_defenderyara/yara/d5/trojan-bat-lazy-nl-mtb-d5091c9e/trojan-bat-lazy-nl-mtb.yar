rule Trojan_BAT_Lazy_NL_MTB{
	meta:
		description = "Trojan:BAT/Lazy.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 bd 00 00 70 13 04 72 a3 00 00 70 13 05 73 ?? 00 00 0a 13 06 } 		$a_01_1 = {43 6f 6e 71 75 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}