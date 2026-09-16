rule Trojan_BAT_ClipBanker_GD_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {43 6c 69 70 62 6f 61 72 64 } 		$a_80_1 = {52 65 67 65 78 } 		$a_80_2 = {43 6c 69 70 70 65 72 } 		$a_80_3 = {7a 63 61 73 68 } 		$a_80_4 = {62 69 74 63 6f 69 6e 63 61 73 68 } 		$a_80_5 = {28 62 63 31 7c 5b 31 33 5d 29 5b 61 2d 7a 41 2d 48 4a 2d 4e 50 2d 5a 30 2d 39 5d 7b 32 36 2c 33 35 7d } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}