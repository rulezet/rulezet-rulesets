rule Trojan_BAT_Remcos_AR_MTB_14{
	meta:
		description = "Trojan:BAT/Remcos.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 16 0b 2b 21 06 07 9a 0c 08 72 ?? ?? ?? 70 20 00 01 00 00 14 14 14 6f ?? ?? ?? 0a 26 de 03 26 de 00 07 17 58 0b 07 06 8e 69 32 d9 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}