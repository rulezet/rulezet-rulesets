rule Trojan_BAT_XWorm_ARR_MTB{
	meta:
		description = "Trojan:BAT/XWorm.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 0d 11 0d 74 ?? ?? ?? ?? 16 14 1d 20 } 		$a_01_1 = {13 0b 13 11 11 11 14 14 16 } 	condition:
		((#a_03_0  & 1)*15+(#a_01_1  & 1)*5) >=20
 
}