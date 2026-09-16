rule Trojan_BAT_KillMBR_ARAS_MTB{
	meta:
		description = "Trojan:BAT/KillMBR.ARAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_80_0 = {2f 43 20 72 6d 64 69 72 20 2f 73 20 2f 71 20 43 3a 5c 57 69 6e 64 6f 77 73 } 		$a_80_1 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } 		$a_80_2 = {5c 52 65 6c 65 61 73 65 5c 59 50 44 2e 70 64 62 } 	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2) >=6
 
}