rule Trojan_BAT_Hawkeye_AHW_MTB{
	meta:
		description = "Trojan:BAT/Hawkeye.AHW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 0a 2b 59 11 06 17 58 20 00 01 00 00 5d 13 06 08 11 04 11 06 91 58 20 00 01 00 00 5d 0c 11 04 11 06 91 13 0b 11 04 11 06 11 04 08 91 9c 11 04 08 11 0b 9c 11 04 11 06 91 11 04 08 91 58 20 00 01 00 00 5d 13 09 02 50 11 0a 02 50 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}