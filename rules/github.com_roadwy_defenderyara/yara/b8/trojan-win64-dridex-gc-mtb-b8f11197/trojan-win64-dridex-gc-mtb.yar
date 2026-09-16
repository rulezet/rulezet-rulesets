rule Trojan_Win64_Dridex_GC_MTB{
	meta:
		description = "Trojan:Win64/Dridex.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {44 8a 0a 48 81 c1 ?? ?? ?? ?? 44 8a 54 24 ?? 41 80 e2 ?? 44 88 54 24 ?? 89 44 24 2c 48 8b 54 24 ?? 46 8a 14 02 45 28 ca 8b 44 24 ?? 05 ?? ?? ?? ?? 44 8b 5c 24 ?? 4c 8b 44 24 ?? 48 8b 74 24 ?? 46 88 14 06 48 89 4c 24 ?? 41 39 c3 0f 84 } 		$a_80_1 = {61 69 6e 63 6c 75 64 69 6e 67 31 70 } 		$a_80_2 = {72 61 69 73 69 6e 67 6e 35 38 37 } 	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=12
 
}