rule Trojan_Win64_Tedy_ARA_MTB_5{
	meta:
		description = "Trojan:Win64/Tedy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 31 c2 8b 84 24 ?? ?? 00 00 48 98 48 31 c2 8b 84 24 ?? ?? 00 00 48 98 48 89 94 c4 ?? ?? 00 00 83 ac 24 ?? ?? 00 00 01 83 bc 24 ?? ?? 00 00 00 79 91 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}