rule Trojan_BAT_Seraph_AMBA_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 0a 11 07 11 05 11 07 28 ?? 00 00 06 20 ?? ?? 00 00 61 d1 9d } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}