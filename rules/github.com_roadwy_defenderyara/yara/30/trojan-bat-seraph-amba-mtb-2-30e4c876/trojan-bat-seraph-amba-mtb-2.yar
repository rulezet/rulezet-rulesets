rule Trojan_BAT_Seraph_AMBA_MTB_2{
	meta:
		description = "Trojan:BAT/Seraph.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 06 11 03 11 01 11 03 91 11 00 59 d2 9c 20 ?? 00 00 00 38 ?? ff ff ff 00 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}