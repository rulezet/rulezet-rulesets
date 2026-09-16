rule Trojan_BAT_Zusy_SJ_MTB{
	meta:
		description = "Trojan:BAT/Zusy.SJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {11 09 11 0a 25 17 58 13 0a 07 11 0b 91 9c 11 0b 17 58 13 0b 11 0b 11 04 11 08 58 32 e3 11 08 8d 06 00 00 01 13 0c 06 73 24 00 00 0a 13 0d 11 0d 11 0c 6f 25 00 00 0a 16 13 0e 2b 21 } 		$a_81_1 = {24 37 37 34 62 39 32 35 33 2d 61 30 62 33 2d 34 34 64 66 2d 39 34 31 62 2d 34 65 38 63 32 33 38 65 33 37 38 37 } 	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}