rule Trojan_BAT_Jalapeno_NJ_MTB_2{
	meta:
		description = "Trojan:BAT/Jalapeno.NJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {08 94 13 09 11 04 11 09 19 5a 11 09 18 63 59 6a 58 13 04 11 04 11 04 1b 62 11 04 19 63 60 61 13 04 11 08 17 58 13 08 } 		$a_01_1 = {4d 61 72 69 75 73 7a 20 4b 6f 6d 6f 72 6f 77 73 6b 69 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}