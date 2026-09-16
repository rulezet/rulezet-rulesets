rule Trojan_BAT_Remcos_ARO_MTB_7{
	meta:
		description = "Trojan:BAT/Remcos.ARO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 1b 8d 41 00 00 01 25 16 28 ?? 00 00 06 6f ?? 00 00 06 a2 25 17 07 72 ?? 02 00 70 6f ?? 00 00 0a 75 ?? 00 00 01 a2 25 18 07 72 ?? 02 00 70 6f ?? 00 00 0a 75 ?? 00 00 01 a2 25 19 07 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}