rule Trojan_BAT_Heracles_NH_MTB_6{
	meta:
		description = "Trojan:BAT/Heracles.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 d2 00 00 06 6f 89 01 00 0a 0d 28 cd 00 00 06 13 04 11 04 39 30 00 00 00 11 04 6f 15 00 00 0a 16 3e 23 00 00 00 11 04 20 40 0f 00 00 28 6d 00 00 06 } 		$a_01_1 = {28 7a 01 00 0a 11 04 6f 89 01 00 0a 0d 04 8e 69 28 c6 01 00 0a 13 05 1f 0e 09 8e 69 58 04 8e 69 58 8d a9 00 00 01 13 06 11 06 16 16 9c 07 16 11 06 17 1e 28 60 01 00 0a 11 06 1f 09 09 8e } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3) >=5
 
}