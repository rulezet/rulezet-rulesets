rule Trojan_BAT_Tedy_ATD_MTB_4{
	meta:
		description = "Trojan:BAT/Tedy.ATD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {13 04 08 06 1a 06 8e b7 1a da 6f 3a 00 00 0a 11 04 17 da 17 d6 8d 2f 00 00 01 0d 08 16 6a 6f 3b 00 00 0a 08 16 73 3c 00 00 0a 13 05 11 05 09 16 09 8e b7 } 		$a_01_1 = {6c 00 6f 00 76 00 65 00 49 00 6e 00 76 00 6f 00 6b 00 65 00 68 00 61 00 70 00 70 00 79 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}