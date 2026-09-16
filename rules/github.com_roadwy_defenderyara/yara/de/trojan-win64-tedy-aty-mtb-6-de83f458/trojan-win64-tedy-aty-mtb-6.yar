rule Trojan_Win64_Tedy_ATY_MTB_6{
	meta:
		description = "Trojan:Win64/Tedy.ATY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f b6 45 e0 88 85 f0 14 00 00 0f 28 45 c0 0f 28 4d d0 0f 29 8d e0 14 00 00 0f 29 85 d0 14 00 00 31 c9 31 d2 49 89 f8 ff 15 14 49 01 00 } 		$a_01_1 = {48 8b d7 4c 8b 4d c7 4b 8b 8c cb 20 32 05 00 48 03 ca 8a 04 32 42 88 44 f9 3e ff c7 48 ff c2 48 63 c7 } 		$a_01_2 = {49 2b f6 4b 8b 8c eb 20 32 05 00 49 03 ce 42 8a 04 36 42 88 44 f9 3e ff c7 49 ff c6 48 63 c7 48 3b c2 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}