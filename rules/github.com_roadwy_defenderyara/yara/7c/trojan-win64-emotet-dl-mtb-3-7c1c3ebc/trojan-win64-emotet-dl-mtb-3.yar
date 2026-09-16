rule Trojan_Win64_Emotet_DL_MTB_3{
	meta:
		description = "Trojan:Win64/Emotet.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b c1 48 2b c2 48 d1 e8 48 03 c2 48 c1 e8 ?? 48 6b c0 ?? 48 2b c8 48 2b cb 8a 44 0c ?? 43 32 04 0b 41 88 01 4c 03 ce 45 3b d4 72 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}