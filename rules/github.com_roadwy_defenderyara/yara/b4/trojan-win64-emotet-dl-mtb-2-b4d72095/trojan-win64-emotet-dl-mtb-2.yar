rule Trojan_Win64_Emotet_DL_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 ff c1 41 f7 e0 41 8b c0 41 ff c0 c1 ea 05 6b d2 29 2b c2 48 63 c8 42 0f b6 04 11 42 32 44 0e ff 41 88 41 ff 44 3b c5 72 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}