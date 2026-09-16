rule Trojan_Win64_Emotet_BR_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.BR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 1f 03 d0 8b c3 ff c3 6b d2 ?? 2b c2 48 63 c8 42 8a 04 09 43 32 04 02 41 88 00 49 ff c0 49 ff cb 74 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}