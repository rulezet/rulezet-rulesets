rule Trojan_BAT_Lazy_KAE_MTB_2{
	meta:
		description = "Trojan:BAT/Lazy.KAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 07 93 28 ?? 00 00 0a 39 ?? 00 00 00 06 07 93 28 ?? 00 00 0a 3a ?? 00 00 00 1f 41 38 ?? 00 00 00 1f 61 0c 06 07 06 07 93 08 59 1f 0d 58 1f 1a 5d 08 58 d1 9d } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}