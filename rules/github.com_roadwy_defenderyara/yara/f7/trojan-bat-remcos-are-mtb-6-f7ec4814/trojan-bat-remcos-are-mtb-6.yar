rule Trojan_BAT_Remcos_ARE_MTB_6{
	meta:
		description = "Trojan:BAT/Remcos.ARE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 06 11 07 6f ?? 00 00 0a 13 08 09 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 00 09 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 00 09 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 00 20 00 1e 01 00 13 09 08 6f ?? 00 00 0a 09 6f ?? 00 00 0a d6 11 09 fe 02 16 fe 01 13 0a 11 0a 2c 0c 00 08 09 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}