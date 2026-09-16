rule Trojan_Win64_Emotet_ARA_MTB_4{
	meta:
		description = "Trojan:Win64/Emotet.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 8b c0 41 83 c0 01 99 83 e2 1f 03 c2 83 e0 1f 2b c2 48 63 c8 48 8d 05 03 c8 08 00 8a 04 01 42 32 04 0f 41 88 01 49 83 c1 01 44 3b c6 72 d1 } 		$a_01_1 = {73 63 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}