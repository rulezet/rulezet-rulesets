rule Trojan_Win64_CobaltStrike_CE_MTB_5{
	meta:
		description = "Trojan:Win64/CobaltStrike.CE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 c6 89 f1 48 8b 15 ?? ?? ?? 00 8b 45 fc 48 98 48 01 d0 89 ca 88 10 83 45 fc 01 eb } 		$a_03_1 = {89 45 fc 8b 45 fc 41 b9 04 00 00 00 41 b8 00 30 00 00 48 89 c2 b9 00 00 00 00 48 8b 05 ?? ?? ?? 00 ff d0 48 89 45 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}