rule Trojan_BAT_RedLine_RDFP_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDFP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 1f 00 00 0a 73 20 00 00 0a 20 20 02 00 00 6f 21 00 00 0a 2a } 		$a_01_1 = {32 61 35 35 62 62 65 61 2d 61 35 35 66 2d 34 36 34 31 2d 61 61 63 37 2d 34 65 30 64 31 62 33 64 65 65 36 35 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}