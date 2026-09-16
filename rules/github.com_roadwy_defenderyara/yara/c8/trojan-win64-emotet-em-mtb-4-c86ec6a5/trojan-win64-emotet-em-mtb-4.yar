rule Trojan_Win64_Emotet_EM_MTB_4{
	meta:
		description = "Trojan:Win64/Emotet.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c7 8b cf 2b c2 ff c7 d1 e8 03 c2 c1 e8 05 6b c0 3f 2b c8 48 63 c1 42 0f b6 04 20 41 32 44 2e ff 41 88 46 ff } 	condition:
		((#a_01_0  & 1)*7) >=7
 
}