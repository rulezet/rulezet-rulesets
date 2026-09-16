rule Trojan_Win64_Emotet_BH_MTB{
	meta:
		description = "Trojan:Win64/Emotet.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 63 c9 0f b6 0c 01 42 32 8c 1c a2 00 00 00 49 83 c3 03 43 88 4c 11 02 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}