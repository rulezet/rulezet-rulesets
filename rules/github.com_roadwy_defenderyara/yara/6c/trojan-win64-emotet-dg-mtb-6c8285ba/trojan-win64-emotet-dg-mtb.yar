rule Trojan_Win64_Emotet_DG_MTB{
	meta:
		description = "Trojan:Win64/Emotet.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {f7 eb 8b cb 03 d3 ff c3 c1 fa 04 8b c2 c1 e8 1f 03 d0 6b c2 1e 2b c8 48 8b 05 [0-04] 48 63 d1 0f b6 0c 02 32 4c 3e ff 88 4f ff 48 83 ed 01 75 } 		$a_01_1 = {38 4f 71 58 3e 77 36 2a 42 6f 73 65 55 38 3e 21 32 35 61 41 46 65 6d 76 32 4c 38 4f 78 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}