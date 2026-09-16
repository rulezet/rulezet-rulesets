rule Trojan_BAT_Mardom_PGMD_MTB_2{
	meta:
		description = "Trojan:BAT/Mardom.PGMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 13 00 00 06 72 01 00 00 70 72 33 00 00 70 72 4d 00 00 70 72 99 00 00 70 6f ?? 00 00 06 20 00 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 ?? ?? 00 00 00 26 20 00 00 00 00 38 04 00 00 00 fe ?? ?? 00 45 01 00 00 00 05 00 00 00 38 00 00 00 00 dd } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}