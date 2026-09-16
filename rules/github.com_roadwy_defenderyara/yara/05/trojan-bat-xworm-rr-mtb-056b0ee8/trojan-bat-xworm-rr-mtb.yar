rule Trojan_BAT_XWorm_RR_MTB{
	meta:
		description = "Trojan:BAT/XWorm.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {58 57 6f 72 6d 43 6c 69 65 6e 74 } 		$a_01_1 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}