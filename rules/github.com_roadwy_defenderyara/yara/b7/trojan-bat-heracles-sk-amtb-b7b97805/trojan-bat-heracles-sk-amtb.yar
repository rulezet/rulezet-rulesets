rule Trojan_BAT_Heracles_SK_AMTB{
	meta:
		description = "Trojan:BAT/Heracles.SK!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_80_0 = {24 45 36 43 34 41 38 46 32 2d 39 44 35 42 2d 34 41 37 45 2d 42 33 46 39 2d 31 43 36 41 38 44 34 45 32 42 37 46 } 		$a_80_1 = {24 24 6d 65 74 68 6f 64 30 78 36 30 30 30 33 33 31 2d 31 } 		$a_80_2 = {42 6f 6e 6b 20 53 74 61 74 69 6f 6e 2e 64 6c 6c } 	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1) >=5
 
}