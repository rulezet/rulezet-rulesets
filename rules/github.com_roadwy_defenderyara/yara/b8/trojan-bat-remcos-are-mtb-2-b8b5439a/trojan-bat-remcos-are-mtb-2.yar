rule Trojan_BAT_Remcos_ARE_MTB_2{
	meta:
		description = "Trojan:BAT/Remcos.ARE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 16 13 08 2b 13 00 07 08 11 08 09 28 ?? 00 00 06 00 00 11 08 17 58 13 08 11 08 07 6f ?? 00 00 0a 2f 0b 08 6f ?? 00 00 0a 09 fe 04 2b 01 16 13 09 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}