rule Trojan_Win64_Tedy_ARA_MTB_2{
	meta:
		description = "Trojan:Win64/Tedy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 55 10 48 8b 45 f8 48 01 d0 0f b6 00 48 8b 4d 10 48 8b 55 f8 48 01 ca 32 45 f7 88 02 48 83 45 f8 01 48 8b 45 f8 48 3b 45 18 72 d3 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}