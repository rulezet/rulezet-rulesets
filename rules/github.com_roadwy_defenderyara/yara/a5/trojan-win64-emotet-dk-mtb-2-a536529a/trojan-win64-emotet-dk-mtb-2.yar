rule Trojan_Win64_Emotet_DK_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 ef c1 fa 04 ff c7 8b c2 c1 e8 1f 03 d0 6b c2 26 2b c8 48 63 c1 48 8d 0d [0-04] 8a 04 08 42 32 04 36 41 88 06 49 ff c6 3b fd 72 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}