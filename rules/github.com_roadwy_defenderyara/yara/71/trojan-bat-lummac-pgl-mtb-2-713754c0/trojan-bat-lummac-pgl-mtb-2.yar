rule Trojan_BAT_Lummac_PGL_MTB_2{
	meta:
		description = "Trojan:BAT/Lummac.PGL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 2e 11 2b 11 2d 91 58 28 ?? 00 00 0a 72 f8 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 5d 13 2e 20 ?? 00 00 00 fe 0e 33 00 38 9f fc ff ff 16 13 2e 38 0d 00 00 00 16 13 2d 20 ?? 00 00 00 38 8e fc ff ff } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}