rule Trojan_BAT_ZgRAT_L_MTB{
	meta:
		description = "Trojan:BAT/ZgRAT.L!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 11 04 08 11 04 91 20 ?? ?? 00 00 28 ?? ?? 00 06 11 04 20 ?? ?? 00 00 28 ?? ?? 00 06 28 ?? ?? 00 0a 5d 28 ?? ?? 00 0a 61 d2 9c 11 04 17 58 13 04 11 04 08 8e 69 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}