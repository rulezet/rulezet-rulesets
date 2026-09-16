rule Trojan_BAT_Seraph_NS_MTB{
	meta:
		description = "Trojan:BAT/Seraph.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 0c 00 00 06 2b cd 28 ?? 00 00 0a 2b cc 07 2b cb 6f ?? 00 00 0a 2b c6 6f ?? 00 00 0a 2b cb 28 ?? 00 00 0a 2b c6 } 		$a_01_1 = {44 65 7a 78 67 62 6a } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}