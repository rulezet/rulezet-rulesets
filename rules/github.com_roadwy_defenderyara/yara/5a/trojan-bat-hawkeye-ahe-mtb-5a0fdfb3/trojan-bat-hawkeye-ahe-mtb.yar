rule Trojan_BAT_Hawkeye_AHE_MTB{
	meta:
		description = "Trojan:BAT/Hawkeye.AHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {17 58 20 00 01 00 00 5d 13 07 08 11 05 11 07 91 58 20 00 01 00 00 5d 0c 11 05 11 07 91 13 0b 11 05 11 07 11 05 08 91 9c 11 05 08 11 0b 9c 11 05 11 07 91 11 05 08 91 58 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}