rule Trojan_BAT_RedLine_MF_MTB_2{
	meta:
		description = "Trojan:BAT/RedLine.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 06 08 6f ?? 00 00 0a 00 06 18 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 02 16 03 8e 69 6f ?? 00 00 0a 0d 09 13 04 2b 00 11 04 2a } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}