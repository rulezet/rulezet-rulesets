rule Trojan_BAT_Ursu_AUR_MTB{
	meta:
		description = "Trojan:BAT/Ursu.AUR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 13 07 11 09 11 07 1f 2a 61 d1 13 07 fe 0d 07 00 28 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}