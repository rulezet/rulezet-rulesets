rule Trojan_Win64_Emotet_AG_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b cf f7 ef ff c7 d1 fa 8b c2 c1 e8 1f 03 d0 6b c2 37 2b c8 48 8b 05 ?? ?? ?? ?? 48 63 d1 0f b6 0c 02 41 32 0c 36 88 0e } 	condition:
		((#a_03_0  & 1)*3) >=3
 
}