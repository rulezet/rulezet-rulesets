rule Trojan_BAT_Mardom_PGMD_MTB{
	meta:
		description = "Trojan:BAT/Mardom.PGMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 08 1a 5a 18 58 58 47 0d 20 ff 00 00 00 09 59 1f 72 61 d2 13 04 02 7b ?? 00 00 04 07 08 58 11 04 9c 08 17 58 0c 08 02 7b ?? 00 00 04 32 d1 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}