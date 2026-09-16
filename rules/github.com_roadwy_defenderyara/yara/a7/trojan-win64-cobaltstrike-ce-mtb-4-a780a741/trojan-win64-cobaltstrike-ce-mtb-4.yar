rule Trojan_Win64_CobaltStrike_CE_MTB_4{
	meta:
		description = "Trojan:Win64/CobaltStrike.CE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 8b 02 49 83 c1 20 49 83 c2 20 48 ff c9 41 89 41 e0 41 8b 42 e4 41 89 41 e4 41 8b 42 e8 41 89 41 e8 41 8b 42 ec 41 89 41 ec 41 8b 42 f0 41 89 41 f0 41 8b 42 f4 41 89 41 f4 41 8b 42 f8 41 89 41 f8 41 8b 42 fc 41 89 41 fc } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}