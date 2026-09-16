rule Trojan_Win32_Gozi_AN_MTB_2{
	meta:
		description = "Trojan:Win32/Gozi.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 "
		
	strings :
		$a_01_0 = {0f b7 c0 6a 19 99 5b f7 fb 80 c2 61 88 14 31 41 3b cf 72 d7 } 		$a_01_1 = {43 6f 53 65 74 50 72 6f 78 79 42 6c 61 6e 6b 65 74 } 		$a_01_2 = {49 6e 74 65 72 6e 65 74 43 61 6e 6f 6e 69 63 61 6c 69 7a 65 55 72 6c 41 } 		$a_01_3 = {47 65 74 53 69 64 53 75 62 41 75 74 68 6f 72 69 74 79 43 6f 75 6e 74 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=9
 
}