rule Trojan_BAT_StealerC_AMAG_MTB_2{
	meta:
		description = "Trojan:BAT/StealerC.AMAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_80_0 = {4a 70 72 43 6a 38 32 65 59 31 65 37 6d 6a 72 47 78 77 2e 64 31 6f 41 69 59 49 42 59 61 4f 39 44 32 41 39 63 5a } 		$a_80_1 = {77 35 52 57 66 4b 67 62 45 69 72 74 61 4f 4c 57 52 57 2e 46 31 50 36 69 71 53 49 5a 36 48 72 74 41 67 6e 77 72 } 		$a_80_2 = {41 46 31 67 61 44 68 4f 4f 68 4f 64 62 4c 77 4d 6a 71 74 36 } 		$a_80_3 = {62 78 4b 4a 6f 4a 4e 6f 47 4e 47 4c 54 4b 51 4e 39 39 } 	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}