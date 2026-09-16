rule Trojan_Win64_Tedy_ARA_MTB{
	meta:
		description = "Trojan:Win64/Tedy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b7 54 45 40 48 8b 85 ?? ?? ?? ?? 66 89 94 45 f0 02 00 00 48 83 85 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}