rule Trojan_BAT_Lazy_KAE_MTB{
	meta:
		description = "Trojan:BAT/Lazy.KAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {fe 0c 03 00 fe 0c 04 00 fe 0c 02 00 fe 0c 04 00 91 fe 0c 00 00 fe 0c 04 00 fe 0c 00 00 8e 69 5d 91 61 d2 9c fe 0c 04 00 7e ?? 00 00 04 58 fe 0e 04 00 fe 0c 04 00 fe 0c 02 00 8e 69 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}