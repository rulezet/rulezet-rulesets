rule Trojan_Win64_IcedID_AA_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 02 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } 		$a_03_1 = {41 0f b6 c9 4c 8d ?? ?? ?? 48 8d ?? ?? ?? 8d 41 ?? 83 e1 ?? 83 e0 ?? 48 8d 14 8a 41 8b 0c 80 4d 8d 04 80 41 0f b6 00 83 e1 ?? 02 02 41 32 04 31 41 88 04 19 49 ff c1 8b 02 d3 c8 ff c0 89 02 83 e0 ?? 0f b6 c8 41 8b 00 d3 c8 ff c0 41 89 00 48 8b ?? ?? ?? 4c 3b ?? ?? ?? 73 ?? 48 8b ?? ?? ?? eb } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*100) >=101
 
}