rule Trojan_BAT_Heracles_ARA_MTB_5{
	meta:
		description = "Trojan:BAT/Heracles.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {00 09 08 11 04 6f ?? ?? ?? 0a 11 04 1f 0a 5d 59 d1 6f ?? ?? ?? 0a 26 00 11 04 17 58 13 04 11 04 08 6f ?? ?? ?? 0a fe 04 13 05 11 05 2d d2 } 		$a_03_1 = {00 06 02 08 6f ?? ?? ?? 0a 03 08 07 5d 6f ?? ?? ?? 0a 61 d1 6f ?? ?? ?? 0a 26 00 08 17 58 0c 08 02 6f ?? ?? ?? 0a fe 04 0d 09 2d d4 } 		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 41 73 79 6e 63 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}