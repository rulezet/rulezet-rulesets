rule Trojan_Win64_Ulise_AHC_MTB_2{
	meta:
		description = "Trojan:Win64/Ulise.AHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 d0 42 88 04 01 fe cc 41 8a c0 69 c2 ?? ?? ?? ?? 49 ff c0 2b d2 41 f7 f1 49 83 f8 } 		$a_03_1 = {42 8a 44 04 24 31 d0 42 88 04 01 69 c2 ?? ?? ?? ?? e9 ?? ?? ?? ?? 49 ff c0 f8 31 d2 f9 41 f7 f1 41 85 d1 49 81 fb ?? ?? ?? ?? e9 } 	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}