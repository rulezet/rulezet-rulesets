rule Trojan_BAT_SpySnake_MH_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 11 09 07 11 09 9a 1f 10 28 ?? ?? ?? 0a 9c 11 09 17 58 13 09 11 09 07 8e 69 fe 04 13 0a 11 0a 2d de } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}