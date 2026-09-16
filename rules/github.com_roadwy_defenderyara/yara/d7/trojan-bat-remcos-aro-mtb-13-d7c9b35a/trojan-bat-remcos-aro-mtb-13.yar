rule Trojan_BAT_Remcos_ARO_MTB_13{
	meta:
		description = "Trojan:BAT/Remcos.ARO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {26 de f1 02 06 28 ?? 00 00 2b 28 ?? 00 00 2b 28 ?? 00 00 0a 28 ?? 00 00 0a 02 73 ?? 00 00 0a 25 72 ?? 00 00 70 03 28 ?? 00 00 0a 6f ?? 00 00 0a 25 1f 0f 1f 14 73 ?? 00 00 0a 6f ?? 00 00 0a 25 17 6f ?? 00 00 0a 7d } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}