rule Trojan_Win64_Tedy_ARA_MTB_4{
	meta:
		description = "Trojan:Win64/Tedy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 14 01 83 f2 7b 41 88 14 04 48 83 c0 01 48 83 f8 0d 75 eb } 		$a_01_1 = {48 89 c1 45 89 c2 83 e1 03 48 c1 e1 03 41 d3 ea 45 30 14 01 48 83 c0 01 48 39 c2 75 e3 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}