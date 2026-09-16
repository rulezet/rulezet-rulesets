rule Trojan_BAT_RedLine_ME_MTB_2{
	meta:
		description = "Trojan:BAT/RedLine.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 02 16 02 8e 69 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a de 0a 08 2c 06 08 6f ?? ?? ?? 0a dc 07 6f ?? ?? ?? 0a 0d de 14 } 		$a_03_1 = {0b 16 0c 2b 78 06 08 9a 16 9a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 2d 11 06 08 9a 16 9a } 	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}