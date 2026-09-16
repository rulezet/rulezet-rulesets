rule Trojan_BAT_Tedy_ATY_MTB{
	meta:
		description = "Trojan:BAT/Tedy.ATY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 7e ?? 00 00 04 a2 25 17 7e ?? 00 00 04 a2 0b 06 14 28 ?? 00 00 0a 2c 12 06 14 17 8d ?? ?? ?? 01 25 16 07 a2 } 		$a_01_1 = {42 00 6f 00 6e 00 6f 00 73 00 75 00 61 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}