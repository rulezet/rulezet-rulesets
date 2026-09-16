rule Trojan_BAT_Remcos_AAR_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 07 09 6f ?? ?? ?? 0a 00 07 18 6f ?? ?? ?? 0a 00 07 6f ?? ?? ?? 0a 02 16 02 8e 69 6f ?? ?? ?? 0a 13 04 11 04 0a 2b 00 06 2a } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}