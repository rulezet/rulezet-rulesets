rule Trojan_BAT_Heracles_AH_MTB_3{
	meta:
		description = "Trojan:BAT/Heracles.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 1a fe 01 2c 08 72 bf 11 00 70 0a 1b 0c 00 08 1c fe 01 2c 06 07 17 d6 0b 1d 0c 00 08 1b fe 01 2c 07 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}