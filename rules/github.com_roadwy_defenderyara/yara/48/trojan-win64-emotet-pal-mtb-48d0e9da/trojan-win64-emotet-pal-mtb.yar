rule Trojan_Win64_Emotet_PAL_MTB{
	meta:
		description = "Trojan:Win64/Emotet.PAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 89 e0 41 ?? ed 44 [0-08] c1 fa ?? 29 c2 b8 ?? ?? ?? ?? 0f af d0 48 8b 05 ?? ?? ?? ?? 41 29 d4 4d 63 e4 42 0f b6 04 20 32 04 2b 88 04 2e 48 83 c5 01 48 81 fd ?? ?? ?? ?? 74 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}