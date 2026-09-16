rule Trojan_BAT_Heracles_BAI_MTB{
	meta:
		description = "Trojan:BAT/Heracles.BAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 73 11 00 00 0a 13 09 38 00 00 00 00 00 11 09 11 03 16 73 17 00 00 0a 13 08 38 00 00 00 00 00 73 08 00 00 0a 13 06 38 00 00 00 00 00 11 08 11 06 ?? ?? ?? ?? ?? 38 00 00 00 00 11 06 ?? ?? ?? ?? ?? 13 07 38 00 00 00 00 dd 46 ff ff ff 11 06 39 11 00 00 00 38 00 00 00 00 11 06 ?? ?? ?? ?? ?? 38 00 00 00 00 dc } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}