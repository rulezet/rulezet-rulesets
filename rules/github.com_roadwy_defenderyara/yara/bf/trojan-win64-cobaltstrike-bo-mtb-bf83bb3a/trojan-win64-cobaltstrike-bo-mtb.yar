rule Trojan_Win64_CobaltStrike_BO_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 fc 48 8b 45 10 48 01 d0 0f b6 00 84 c0 74 2a 8b 45 fc 8d 50 01 89 55 fc 89 c2 48 8b 45 10 48 01 d0 0f b7 00 66 89 45 f6 0f b7 55 f6 8b 45 f8 c1 c8 08 01 d0 31 45 f8 eb } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}