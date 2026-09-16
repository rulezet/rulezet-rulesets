rule Trojan_Win64_Emotet_EH_MTB_3{
	meta:
		description = "Trojan:Win64/Emotet.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8d 76 01 f7 e7 8b cf ff c7 c1 ea 04 6b c2 34 2b c8 48 63 c1 42 0f b6 04 20 41 32 44 36 ff 88 46 ff } 	condition:
		((#a_01_0  & 1)*7) >=7
 
}