rule Trojan_BAT_Lazy_PGL_MTB_2{
	meta:
		description = "Trojan:BAT/Lazy.PGL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {54 00 65 00 6d 00 70 00 00 13 5c 00 78 00 4c 00 6f 00 6b 00 2e 00 65 00 78 00 65 } 		$a_80_1 = {72 67 73 74 6a 72 65 70 72 65 73 65 6e 74 61 74 69 76 65 64 } 		$a_80_2 = {68 76 79 64 7a 73 70 65 63 69 66 69 63 61 74 69 6f 6e 73 70 } 		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_01_3  & 1)*5) >=10
 
}