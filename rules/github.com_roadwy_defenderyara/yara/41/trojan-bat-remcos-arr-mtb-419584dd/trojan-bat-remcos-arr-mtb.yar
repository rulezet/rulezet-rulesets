rule Trojan_BAT_Remcos_ARR_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 14 7d 07 00 00 04 02 28 ?? ?? ?? 0a 00 00 02 20 f4 01 00 00 28 ?? ?? ?? 0a 00 02 20 bc 02 00 00 28 ?? ?? ?? 0a 00 02 72 01 00 00 70 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}