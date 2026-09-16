rule Trojan_BAT_Hawkeye_AHE_MTB_2{
	meta:
		description = "Trojan:BAT/Hawkeye.AHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0c 0a 2b 37 02 50 06 02 50 8e b7 5d 02 50 06 02 50 8e b7 5d 91 03 06 03 8e b7 5d 91 61 02 50 06 17 d6 02 50 8e b7 5d 91 da 20 00 01 00 00 d6 20 00 01 00 00 5d b4 9c 06 17 d6 0a 06 08 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}