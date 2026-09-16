rule Trojan_BAT_Heracles_BAI_MTB_2{
	meta:
		description = "Trojan:BAT/Heracles.BAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 08 1f 0a 31 7e 11 08 11 04 8e 69 1f 0a 59 2f 73 11 04 11 08 1f 09 59 91 1f 22 33 67 11 04 11 08 1e 59 91 1f 63 33 5c 11 04 11 08 1d 59 91 1f 58 33 51 11 04 11 08 1c 59 91 1f 56 33 46 11 04 11 08 1b 59 91 1f 70 33 3b 11 04 11 08 1a 59 91 1f 64 33 30 11 04 11 08 19 59 91 1f 41 33 25 11 04 11 08 18 59 91 1f 3d 33 1a 11 04 11 08 17 59 91 1f 3d 33 0f 11 04 11 08 91 1f 22 33 06 16 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}