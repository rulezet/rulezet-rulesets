rule Trojan_BAT_Stealerc_SM_MTB{
	meta:
		description = "Trojan:BAT/Stealerc.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 02 08 03 08 91 05 08 06 8e 69 5d 91 61 d2 9c 00 08 17 58 0c 08 03 8e 69 fe 04 0d 09 2d e1 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}