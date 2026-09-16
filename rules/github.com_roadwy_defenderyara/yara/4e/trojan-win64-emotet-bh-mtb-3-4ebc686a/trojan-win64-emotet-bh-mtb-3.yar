rule Trojan_Win64_Emotet_BH_MTB_3{
	meta:
		description = "Trojan:Win64/Emotet.BH!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4d 8d 40 01 f7 e7 8b cf ff c7 c1 ea 05 6b c2 2f 2b c8 48 63 c1 42 0f b6 04 10 43 32 44 07 ff 41 88 40 ff 41 3b fc 72 d3 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}