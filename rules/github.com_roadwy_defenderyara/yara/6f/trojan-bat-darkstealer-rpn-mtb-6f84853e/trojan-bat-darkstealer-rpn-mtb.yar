rule Trojan_BAT_DarkStealer_RPN_MTB{
	meta:
		description = "Trojan:BAT/DarkStealer.RPN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 04 08 5d 91 07 04 1f 16 5d 91 61 28 1f 00 00 0a 03 04 17 58 08 5d 91 28 20 00 00 0a 59 06 58 06 5d d2 0d 2b 00 09 2a } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}