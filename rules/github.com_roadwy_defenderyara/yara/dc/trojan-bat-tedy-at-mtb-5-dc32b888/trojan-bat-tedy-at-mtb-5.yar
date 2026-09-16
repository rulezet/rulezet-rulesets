rule Trojan_BAT_Tedy_AT_MTB_5{
	meta:
		description = "Trojan:BAT/Tedy.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {0b 00 07 0c 16 0d 2b 32 08 09 9a 13 04 00 11 04 25 2d 04 26 14 2b 05 6f 23 00 00 0a 72 a9 a0 00 70 28 36 00 00 0a 0a 06 28 2c 00 00 0a 13 05 11 05 2c 02 2b 0b 00 09 17 58 0d 09 08 8e 69 32 c8 } 		$a_01_1 = {6c 00 6c 00 6f 00 6f 00 73 00 73 00 74 00 74 00 } 		$a_01_2 = {69 00 6f 00 6d 00 44 00 6f 00 6d 00 65 00 2e 00 64 00 6c 00 6c 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}