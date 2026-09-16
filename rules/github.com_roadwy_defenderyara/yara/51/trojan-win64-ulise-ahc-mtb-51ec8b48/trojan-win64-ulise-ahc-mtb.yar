rule Trojan_Win64_Ulise_AHC_MTB{
	meta:
		description = "Trojan:Win64/Ulise.AHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {42 8a 44 04 30 40 f6 c4 ?? 31 d0 42 88 04 01 66 44 0f ab f8 49 0f bf c3 e9 ?? ?? ?? ?? 69 c2 ?? ?? ?? ?? e9 } 		$a_03_1 = {66 41 0f be d0 d3 d2 89 c2 83 e2 ?? f5 f9 8a 14 11 f5 f7 c3 ?? ?? ?? ?? 30 14 03 e9 } 	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}