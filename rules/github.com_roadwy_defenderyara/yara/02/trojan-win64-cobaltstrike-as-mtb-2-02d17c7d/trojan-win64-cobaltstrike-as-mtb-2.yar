rule Trojan_Win64_CobaltStrike_AS_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {4c 01 c0 31 ca 88 10 48 83 45 ?? 01 90 13 48 8b 45 ?? 48 3b 45 ?? 73 ?? 48 8b 55 ?? 48 8b 45 ?? 48 01 d0 0f b6 08 48 8b 45 ?? ba 00 00 00 00 48 f7 75 ?? 48 8b 45 ?? 48 01 d0 0f b6 10 4c 8b 45 10 48 8b 45 } 		$a_03_1 = {48 01 d0 44 89 c2 31 ca 88 10 83 45 ?? 01 83 45 ?? 01 8b 45 ?? 48 98 48 3b 45 ?? 90 13 8b 45 ?? 48 98 48 3b 45 ?? 72 ?? c7 45 ?? 00 00 00 00 8b 45 ?? 48 63 d0 48 8b 45 ?? 48 01 d0 44 0f b6 00 8b 45 ?? 48 63 d0 48 8b 45 ?? 48 01 d0 0f b6 08 8b 45 ?? 48 63 d0 48 8b 45 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}