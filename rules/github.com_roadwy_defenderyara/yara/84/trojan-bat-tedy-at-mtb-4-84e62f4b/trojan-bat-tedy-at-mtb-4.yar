rule Trojan_BAT_Tedy_AT_MTB_4{
	meta:
		description = "Trojan:BAT/Tedy.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 14 00 00 0a 25 72 20 01 00 70 04 6f 15 00 00 0a 00 25 72 32 01 00 70 03 6f 15 00 00 0a 00 28 01 00 00 06 26 2a } 		$a_01_1 = {73 65 6e 64 57 65 62 48 6f 6f 6b } 		$a_01_2 = {57 00 65 00 62 00 20 00 44 00 72 00 6f 00 70 00 70 00 65 00 72 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}