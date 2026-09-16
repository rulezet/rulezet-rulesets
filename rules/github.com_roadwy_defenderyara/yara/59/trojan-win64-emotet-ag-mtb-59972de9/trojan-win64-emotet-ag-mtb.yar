rule Trojan_Win64_Emotet_AG_MTB{
	meta:
		description = "Trojan:Win64/Emotet.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b cb f7 eb ff c3 c1 fa 04 8b c2 c1 e8 1f 03 d0 6b c2 35 2b c8 48 63 c1 42 8a 0c 08 43 32 0c 02 41 88 08 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}