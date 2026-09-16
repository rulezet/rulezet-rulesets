rule Trojan_Win64_Emotet_PAI_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.PAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {b8 43 08 21 84 8b cb 48 8d 7f 01 f7 eb 03 d3 ff c3 c1 fa 05 8b c2 c1 e8 1f 03 d0 6b c2 3e 2b c8 48 8b 05 ?? ?? ?? ?? 48 63 d1 0f b6 0c 02 32 4c 3e ff 88 4f ff 49 ff cf 75 b9 48 8d 0d 42 8e 02 } 		$a_01_1 = {b8 89 88 88 88 f7 ef 03 d7 c1 fa 05 8b c2 c1 e8 1f 03 d0 8b c7 ff c7 6b d2 3c 2b c2 48 63 c8 42 8a 04 09 43 32 04 02 41 88 00 49 ff c0 48 ff ce 74 09 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}