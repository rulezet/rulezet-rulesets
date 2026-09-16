rule Trojan_BAT_Seraph_AAUU_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AAUU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 77 65 66 6a 69 } 		$a_01_1 = {4d 68 65 75 72 66 67 } 		$a_01_2 = {50 69 75 73 72 68 67 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}