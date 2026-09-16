rule Trojan_BAT_Lazy_PGY_MTB{
	meta:
		description = "Trojan:BAT/Lazy.PGY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {12 00 20 00 0b fc ff 1d 63 66 20 00 f6 ff ff 18 63 65 1d 63 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}