rule Trojan_Win64_Foosace_K_dha{
	meta:
		description = "Trojan:Win64/Foosace.K!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {48 b9 22 2c 20 49 6e 69 74 57 48 89 4c 38 0e 66 c7 44 38 16 20 00 } 		$a_03_1 = {48 b8 33 32 2e 45 58 45 20 22 48 89 85 ?? ?? ?? ?? 48 b8 52 55 4e 44 4c 4c 33 32 } 	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}