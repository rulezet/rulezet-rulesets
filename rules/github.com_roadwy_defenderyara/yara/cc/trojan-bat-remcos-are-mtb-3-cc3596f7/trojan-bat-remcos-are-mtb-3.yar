rule Trojan_BAT_Remcos_ARE_MTB_3{
	meta:
		description = "Trojan:BAT/Remcos.ARE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 2b 33 02 0d 16 13 04 09 12 04 28 ?? 00 00 0a 07 06 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a de 0b 11 04 2c 06 09 28 ?? 00 00 0a dc 08 18 58 0c 08 06 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}