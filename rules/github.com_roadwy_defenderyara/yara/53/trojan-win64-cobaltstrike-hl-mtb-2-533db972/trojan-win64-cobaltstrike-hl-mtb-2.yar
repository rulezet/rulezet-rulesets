rule Trojan_Win64_Cobaltstrike_HL_MTB_2{
	meta:
		description = "Trojan:Win64/Cobaltstrike.HL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 0f b6 08 8b c3 99 41 f7 fa 48 63 c2 42 0f b6 14 38 2b ca 81 c1 ?? ?? ?? ?? 81 e1 ?? ?? ?? ?? 7d ?? ff c9 81 c9 ?? ?? ?? ?? ff c1 41 88 08 ff c3 49 ff c0 49 83 e9 01 75 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}