rule Trojan_BAT_Heracles_NH_MTB_2{
	meta:
		description = "Trojan:BAT/Heracles.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {0c 11 04 08 59 0d 02 7b 61 00 00 04 09 0e 04 0e 05 08 28 bb 00 00 0a 08 2a } 		$a_01_1 = {4a 48 4f 4e 4e 45 54 20 53 55 50 52 45 4d 45 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}