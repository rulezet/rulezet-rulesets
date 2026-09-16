rule Trojan_BAT_Stealer_SN_MTB{
	meta:
		description = "Trojan:BAT/Stealer.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 11 04 11 0a 02 11 0a 91 03 11 0a 03 6f 16 00 00 0a 5d 6f 17 00 00 0a 61 d2 9c 00 11 0a 17 58 13 0a 11 0a 02 8e 69 fe 04 13 0b 11 0b 3a ce ff ff ff } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}