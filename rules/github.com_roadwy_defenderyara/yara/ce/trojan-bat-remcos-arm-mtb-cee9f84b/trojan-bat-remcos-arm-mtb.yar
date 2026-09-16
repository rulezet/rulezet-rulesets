rule Trojan_BAT_Remcos_ARM_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 1f 1f 5a 11 06 1f 11 5a 58 09 74 ?? ?? ?? 1b 8e 69 17 59 5f 13 08 11 1b 20 ?? ?? ?? ?? 91 19 5b 13 1a } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}