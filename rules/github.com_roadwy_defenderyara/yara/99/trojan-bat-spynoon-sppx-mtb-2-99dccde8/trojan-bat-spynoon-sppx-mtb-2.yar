rule Trojan_BAT_SpyNoon_SPPX_MTB_2{
	meta:
		description = "Trojan:BAT/SpyNoon.SPPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 0c 07 11 04 11 0c d2 9c } 	condition:
		((#a_01_0  & 1)*4) >=4
 
}