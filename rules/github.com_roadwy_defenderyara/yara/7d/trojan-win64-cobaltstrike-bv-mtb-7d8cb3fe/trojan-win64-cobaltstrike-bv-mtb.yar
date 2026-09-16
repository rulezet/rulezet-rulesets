rule Trojan_Win64_CobaltStrike_BV_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 f7 e2 48 d1 ea 48 89 d0 48 01 c0 48 01 d0 48 29 c1 48 89 ca 0f b6 84 15 [0-04] 44 89 c1 31 c1 48 8b 95 [0-04] 8b 85 [0-04] 48 98 88 0c 02 83 85 [0-04] 01 8b 95 [0-04] 8b 85 [0-04] 39 c2 72 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}