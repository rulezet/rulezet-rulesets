rule Trojan_BAT_CobaltStrike_MB_MTB{
	meta:
		description = "Trojan:BAT/CobaltStrike.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {1f 40 28 02 00 00 06 0b 06 16 07 06 8e 69 28 09 00 00 0a 07 d0 03 00 00 02 28 0a 00 00 0a 28 0b 00 00 0a 75 03 00 00 02 0c 08 6f 0c 00 00 06 26 de 0e 07 16 20 00 80 00 00 28 03 00 00 06 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}