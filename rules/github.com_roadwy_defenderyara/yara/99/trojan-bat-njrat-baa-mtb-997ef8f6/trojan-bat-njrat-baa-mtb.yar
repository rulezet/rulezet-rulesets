rule Trojan_BAT_NjRat_BAA_MTB{
	meta:
		description = "Trojan:BAT/NjRat.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 11 09 11 0d 11 0e 11 0c 11 0e 59 ?? ?? ?? ?? ?? 13 0f 11 0f 16 fe 01 16 fe 01 13 13 11 13 2d 02 2b 14 11 0e 11 0f 58 13 0e 00 11 0e 11 0c fe 04 13 13 11 13 2d c9 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}