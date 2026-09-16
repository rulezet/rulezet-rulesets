rule Trojan_BAT_Crysan_ACR_MTB_4{
	meta:
		description = "Trojan:BAT/Crysan.ACR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 01 00 00 06 0a 06 16 28 02 00 00 06 26 28 04 00 00 06 6f 05 00 00 0a 2a } 		$a_01_1 = {7d 04 00 00 04 12 00 7b 05 00 00 04 0b 12 01 12 00 28 02 00 00 2b 12 00 7c 05 00 00 04 28 28 00 00 0a 2a } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}