rule Trojan_BAT_SpySnake_MG_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 09 07 09 9a 1f 10 28 ?? ?? ?? 0a 9c 09 17 d6 0d 00 09 07 8e 69 fe 04 13 05 11 05 2d e2 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}