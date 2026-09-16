rule Trojan_Win64_Cobaltstrike_FG_MTB_2{
	meta:
		description = "Trojan:Win64/Cobaltstrike.FG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 44 0c ?? 42 32 44 0f ?? 41 88 41 ?? 41 8d 42 ?? 41 83 c2 04 48 63 c8 49 8b c0 48 f7 e1 48 c1 ea 02 48 6b c2 16 48 2b c8 0f b6 44 0c ?? 42 32 44 0e ?? 41 88 41 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}