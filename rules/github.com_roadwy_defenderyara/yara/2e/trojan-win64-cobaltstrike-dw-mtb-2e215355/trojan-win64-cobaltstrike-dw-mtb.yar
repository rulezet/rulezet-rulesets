rule Trojan_Win64_Cobaltstrike_DW_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.DW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {c1 f8 08 48 c1 f9 08 0f b6 d1 32 84 3a 80 01 04 00 88 46 fe 43 8d 04 3a 99 41 ff c7 f7 fd 48 63 c2 0f b6 8c 83 58 04 00 00 44 32 84 39 80 01 04 00 44 88 46 ff 4d 3b cd 0f } 		$a_03_1 = {44 89 64 24 30 4c 8d 4c 24 30 ba 08 00 00 00 44 8d 42 38 49 8b ce ff 15 ?? ?? 02 00 33 c9 ff 15 } 	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}