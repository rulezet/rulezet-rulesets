rule Trojan_Win64_CobaltStrike_BN_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 55 c0 8b 85 [0-04] 48 98 48 01 d0 44 0f b6 00 8b 85 [0-04] 48 98 0f b6 4c 05 ca 48 8b 55 c0 8b 85 [0-04] 48 98 48 01 d0 44 89 c2 31 ca 88 10 83 85 [0-04] 01 83 85 [0-04] 01 eb } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}