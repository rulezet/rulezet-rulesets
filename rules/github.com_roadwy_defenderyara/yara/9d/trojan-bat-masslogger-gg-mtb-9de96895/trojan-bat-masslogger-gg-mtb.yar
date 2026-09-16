rule Trojan_BAT_Masslogger_GG_MTB{
	meta:
		description = "Trojan:BAT/Masslogger.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_80_0 = {6d 61 73 73 6c 6f 67 67 65 72 } 		$a_80_1 = {50 61 73 73 77 6f 72 64 } 		$a_80_2 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } 		$a_80_3 = {47 65 74 4b 65 79 62 6f 61 72 64 53 74 61 74 65 } 		$a_80_4 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } 		$a_80_5 = {48 4f 4f 4b 2f 4d 45 4d 4f 52 59 36 } 	condition:
		((#a_80_0  & 1)*15+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=18
 
}