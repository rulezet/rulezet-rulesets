rule Trojan_BAT_Msilheracles_PGM_MTB{
	meta:
		description = "Trojan:BAT/Msilheracles.PGM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_80_0 = {49 55 64 6c 74 48 47 59 64 67 50 5a 65 49 61 4e 4e 49 72 4a 76 58 6d 4c 6c 64 2e 6b 6a 76 76 45 48 79 4f 6d 79 53 46 45 59 64 6c 66 45 79 4d 78 52 49 7a 68 4f 6e } 		$a_80_1 = {65 4f 6d 6e 57 61 42 54 76 4d 43 77 4e 46 51 63 77 6c 5a 41 53 76 79 45 57 4a 52 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*4) >=5
 
}