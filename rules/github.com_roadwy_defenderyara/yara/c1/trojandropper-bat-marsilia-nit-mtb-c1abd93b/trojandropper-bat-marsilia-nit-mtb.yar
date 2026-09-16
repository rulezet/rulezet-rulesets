rule TrojanDropper_BAT_Marsilia_NIT_MTB{
	meta:
		description = "TrojanDropper:BAT/Marsilia.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 6f 1c 00 00 0a 73 19 00 00 0a 13 06 1a 8d 1a 00 00 01 13 07 11 06 11 07 16 1a 6f ?? 00 00 0a 26 11 07 16 28 ?? 00 00 0a 13 08 11 06 16 73 1f 00 00 0a 13 09 11 09 11 05 6f ?? 00 00 0a 73 20 00 00 0a 13 0a 11 0a 11 05 6f ?? 00 00 0a 6f ?? 00 00 0a 11 0a 13 0a dd 63 00 00 00 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}