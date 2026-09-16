rule Trojan_BAT_Remcos_ARM_MTB_8{
	meta:
		description = "Trojan:BAT/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 16 9a 13 04 19 8d ?? 00 00 01 25 16 02 7b ?? 00 00 04 a2 25 17 02 7b ?? 00 00 04 a2 25 18 72 ?? 08 00 70 a2 13 05 72 ?? 08 00 70 17 8d ?? 00 00 01 25 16 1f 58 9d 28 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}