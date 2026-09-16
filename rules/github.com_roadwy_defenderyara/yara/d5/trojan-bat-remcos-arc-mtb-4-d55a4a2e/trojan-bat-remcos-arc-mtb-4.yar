rule Trojan_BAT_Remcos_ARC_MTB_4{
	meta:
		description = "Trojan:BAT/Remcos.ARC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 16 0c 16 0c 2b 63 03 08 03 8e 69 5d 1f 20 59 1f 20 58 03 08 03 8e 69 5d 1f 09 58 1f 0e 58 1f 17 59 91 07 08 07 8e 69 5d 1f 09 58 1f 0e 58 1f 17 59 91 61 28 ?? ?? ?? 0a 03 08 20 8a 10 00 00 58 20 89 10 00 00 59 03 8e 69 5d 1f 09 58 1f 0e 58 1f 17 59 91 59 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}