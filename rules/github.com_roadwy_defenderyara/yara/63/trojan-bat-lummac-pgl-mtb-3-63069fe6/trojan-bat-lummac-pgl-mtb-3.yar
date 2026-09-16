rule Trojan_BAT_Lummac_PGL_MTB_3{
	meta:
		description = "Trojan:BAT/Lummac.PGL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 07 38 e3 ff ff ff 28 ?? 00 00 0a 11 01 11 08 1e 6f ?? 00 00 0a 17 8d ?? 00 00 01 6f ?? 00 00 0a 28 ?? 00 00 06 28 ?? 00 00 0a 72 02 01 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 39 b0 ff ff ff 38 17 00 00 00 11 01 11 02 1c 58 28 ?? 00 00 0a 13 03 20 03 00 00 00 38 eb fd ff ff 11 01 11 08 1f 14 58 28 ?? 00 00 0a 13 09 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}