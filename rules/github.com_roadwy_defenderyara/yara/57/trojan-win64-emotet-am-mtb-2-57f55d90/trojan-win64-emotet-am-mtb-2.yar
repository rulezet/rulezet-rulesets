rule Trojan_Win64_Emotet_AM_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 d0 8b c3 ff c3 6b d2 ?? 2b c2 48 63 c8 42 8a 04 19 43 32 04 01 41 88 00 49 ff c0 48 83 ef 01 74 09 } 	condition:
		((#a_03_0  & 1)*3) >=3
 
}