rule Trojan_Win64_Emotet_BE_MTB{
	meta:
		description = "Trojan:Win64/Emotet.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b c2 c1 e8 ?? 03 d0 8b c3 ff c3 6b d2 ?? 2b c2 48 63 d0 48 8b 05 ?? ?? ?? ?? 8a 14 02 41 32 [0-04] 88 17 48 ff c7 49 [0-04] 75 } 		$a_03_1 = {ff c8 83 c8 ?? ff c0 48 63 d0 48 8b 05 ?? ?? ?? ?? ff c6 8a 14 02 41 32 14 1e 88 13 48 ff c3 49 ff cd 75 } 		$a_01_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}