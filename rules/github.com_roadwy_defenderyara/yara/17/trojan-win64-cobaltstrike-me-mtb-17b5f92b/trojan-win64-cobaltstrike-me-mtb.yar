rule Trojan_Win64_CobaltStrike_ME_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {43 33 1c 87 45 89 e0 41 c1 ec 08 45 0f b6 e4 47 0f b6 24 23 4c 8d 3d 29 99 0e 00 43 33 1c a7 45 0f b6 c0 47 0f b6 04 18 4c 8d 25 15 9d 0e 00 43 33 1c 84 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}