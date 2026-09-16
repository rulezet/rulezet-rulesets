rule Trojan_BAT_ClipBanker_GF_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {43 6c 69 70 62 6f 61 72 64 } 		$a_80_1 = {42 54 43 20 53 74 65 61 6c 65 72 } 		$a_80_2 = {5e 5b 31 33 5d 5b 61 2d 6b 6d 2d 7a 41 2d 48 4a 2d 4e 50 2d 5a 30 2d 39 5d 7b 32 36 2c 33 33 7d 24 } 		$a_80_3 = {42 69 74 43 6f 69 6e } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}