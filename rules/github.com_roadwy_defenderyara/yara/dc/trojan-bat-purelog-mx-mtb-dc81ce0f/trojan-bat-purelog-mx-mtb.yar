rule Trojan_BAT_Purelog_MX_MTB{
	meta:
		description = "Trojan:BAT/Purelog.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {51 69 62 61 6e 6f 6e 61 6e 61 2e 70 64 62 } 		$a_80_1 = {53 32 75 6d 34 44 58 59 41 78 75 66 57 52 72 68 46 77 2e 67 6c 62 41 67 75 50 57 50 6f 30 48 63 36 51 55 67 4a } 		$a_80_2 = {69 73 20 74 61 6d 70 65 72 65 64 } 		$a_80_3 = {44 65 62 75 67 67 65 72 20 44 65 74 65 63 74 65 64 } 	condition:
		((#a_00_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}