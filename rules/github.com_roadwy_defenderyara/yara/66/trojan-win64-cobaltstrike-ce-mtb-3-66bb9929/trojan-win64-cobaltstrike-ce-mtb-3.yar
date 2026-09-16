rule Trojan_Win64_CobaltStrike_CE_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.CE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 98 4c 89 ca 48 29 c2 48 8b 45 ?? 48 01 d0 0f b6 10 8b 45 ?? 01 d0 44 31 c0 88 01 83 45 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}