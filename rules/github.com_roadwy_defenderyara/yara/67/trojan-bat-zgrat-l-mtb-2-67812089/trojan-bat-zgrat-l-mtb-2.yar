rule Trojan_BAT_ZgRAT_L_MTB_2{
	meta:
		description = "Trojan:BAT/ZgRAT.L!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {91 61 d2 9c 90 09 0e 00 02 11 ?? 02 11 ?? 91 03 11 ?? 03 8e 69 5d } 		$a_03_1 = {16 1f 20 9d 11 ?? 6f ?? 00 00 0a 13 ?? 20 90 09 0d 00 02 16 9a 17 8d ?? 00 00 01 13 ?? 11 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}