rule Trojan_BAT_Remcos_ARR_MTB_2{
	meta:
		description = "Trojan:BAT/Remcos.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 0d 11 0d 2c 0a 00 0f 03 28 ?? ?? ?? 0a 00 00 02 08 06 7b ?? 00 00 04 6f ?? 00 00 0a 13 05 03 07 6f ?? 00 00 0a 59 13 06 11 05 28 ?? 00 00 06 13 07 07 11 07 16 91 6f ?? ?? ?? 0a 00 11 06 17 59 25 13 06 16 fe 02 16 fe 01 13 0e 11 0e 2c 05 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}