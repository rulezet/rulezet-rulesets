rule Trojan_BAT_Seraph_NSE_MTB_2{
	meta:
		description = "Trojan:BAT/Seraph.NSE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 01 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 06 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 28 ?? 00 00 06 75 ?? 00 00 1b 73 ?? 00 00 0a 0d 09 07 16 73 18 00 00 0a } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}