rule Trojan_BAT_Barys_ARA_MTB_2{
	meta:
		description = "Trojan:BAT/Barys.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 11 17 11 19 58 06 11 19 58 47 11 05 11 19 11 05 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 d2 52 00 11 19 17 58 13 19 11 19 11 10 8e 69 fe 04 13 1a 11 1a 2d cc } 		$a_01_1 = {3c 53 48 49 45 4c 44 3e } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}