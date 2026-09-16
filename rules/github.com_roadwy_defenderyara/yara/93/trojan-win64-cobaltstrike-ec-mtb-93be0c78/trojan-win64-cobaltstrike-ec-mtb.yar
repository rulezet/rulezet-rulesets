rule Trojan_Win64_CobaltStrike_EC_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8d 47 08 49 8d 54 3d 07 66 0f 1f 84 00 00 00 00 00 0f b6 08 49 89 d0 49 29 c0 48 83 c0 01 48 39 d0 4c 89 44 cc 20 75 e9 } 	condition:
		((#a_01_0  & 1)*7) >=7
 
}