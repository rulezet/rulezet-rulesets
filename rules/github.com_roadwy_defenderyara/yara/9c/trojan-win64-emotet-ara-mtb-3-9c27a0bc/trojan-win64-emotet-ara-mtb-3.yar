rule Trojan_Win64_Emotet_ARA_MTB_3{
	meta:
		description = "Trojan:Win64/Emotet.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 f7 e8 c1 fa 04 8b c2 c1 e8 1f 03 d0 41 8b c0 41 ff c0 8d 0c 92 c1 e1 03 2b c1 48 63 c8 48 8d 05 be 74 08 00 8a 04 01 41 32 04 2a 41 88 02 49 ff c2 45 3b c6 72 c4 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}