rule Trojan_BAT_NjRAT_NR_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {26 08 09 02 09 91 11 04 11 04 06 84 95 11 04 07 84 95 d7 6e ?? ?? ?? ?? ?? 6a 5f b7 95 61 86 9c } 	condition:
		((#a_03_0  & 1)*3) >=3
 
}