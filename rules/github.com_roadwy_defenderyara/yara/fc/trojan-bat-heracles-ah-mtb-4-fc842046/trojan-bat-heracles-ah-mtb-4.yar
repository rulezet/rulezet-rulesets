rule Trojan_BAT_Heracles_AH_MTB_4{
	meta:
		description = "Trojan:BAT/Heracles.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 8e 2d 0a 12 01 fe 15 02 00 00 1b 07 2a 7e ?? ?? ?? 0a 0a 02 7b ?? ?? ?? 04 0a 03 16 06 03 8e 69 28 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}