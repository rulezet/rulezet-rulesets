rule Trojan_BAT_Stealer_ARA_MTB_3{
	meta:
		description = "Trojan:BAT/Stealer.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_80_0 = {43 3a 5c 55 73 65 72 73 5c 41 68 6d 65 64 5c 44 6f 63 75 6d 65 6e 74 73 5c 56 69 73 75 61 6c 20 53 74 75 64 69 6f 20 32 30 31 30 5c 50 72 6f 6a 65 63 74 73 5c 70 6c 61 5c 42 6f 6f 74 6d 67 72 5c 6f 62 6a 5c 78 38 36 5c 44 65 62 75 67 5c 42 6f 6f 74 6d 67 72 2e 70 64 62 } 		$a_80_1 = {43 3a 5c 42 6f 6f 74 5c 42 6f 6f 74 6d 67 72 2e 63 6f 6d } 		$a_80_2 = {63 3a 5c 62 6f 6f 74 5c 6d 65 2e 64 6c 6c } 		$a_80_3 = {6c 6f 67 2e 74 78 74 } 	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2) >=8
 
}