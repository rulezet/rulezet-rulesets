rule Trojan_BAT_Redline_GEH_MTB{
	meta:
		description = "Trojan:BAT/Redline.GEH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_03_0 = {04 06 18 28 ?? ?? ?? 06 16 2d f1 7e ?? ?? ?? ?? 06 28 ?? ?? ?? 06 0d 7e ?? ?? ?? ?? 09 03 16 03 8e 69 28 ?? ?? ?? 06 13 04 1e } 		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } 		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } 		$a_01_3 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=13
 
}