rule Trojan_Win64_Emotet_ARA_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 f7 e8 41 ff c0 c1 fa 03 8b c2 c1 e8 1f 03 d0 6b c2 2c 2b c8 48 63 c1 48 8d 0d c9 60 08 00 8a 04 08 41 32 04 2a 41 88 02 49 ff c2 45 3b c6 72 c7 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}