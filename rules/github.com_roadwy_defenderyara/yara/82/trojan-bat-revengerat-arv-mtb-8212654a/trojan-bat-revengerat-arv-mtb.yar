rule Trojan_BAT_RevengeRat_ARV_MTB{
	meta:
		description = "Trojan:BAT/RevengeRat.ARV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 12 02 1f 64 14 0d 12 03 1f 64 28 ?? ?? ?? 06 2c 08 72 ?? ?? ?? 70 0a de 1c 07 17 ?? 0b 07 1a 31 d5 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}