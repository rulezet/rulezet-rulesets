rule Trojan_Win64_Latrodectus_PG_MTB_2{
	meta:
		description = "Trojan:Win64/Latrodectus.PG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {4d 2b d1 4e 8d 04 0b 48 8b cb 48 b8 cd cc cc cc cc cc cc cc 48 f7 e3 48 c1 ea ?? 48 ff c3 48 8d ?? 92 48 c1 e0 ?? 48 2b c8 8a 44 0d ?? 43 32 04 02 41 88 00 48 81 fb [0-04] 72 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}