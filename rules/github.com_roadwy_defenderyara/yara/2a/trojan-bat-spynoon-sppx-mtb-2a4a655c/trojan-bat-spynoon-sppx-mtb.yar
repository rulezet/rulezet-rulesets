rule Trojan_BAT_SpyNoon_SPPX_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.SPPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {5d 13 06 07 11 06 91 13 07 08 09 } 	condition:
		((#a_01_0  & 1)*4) >=4
 
}