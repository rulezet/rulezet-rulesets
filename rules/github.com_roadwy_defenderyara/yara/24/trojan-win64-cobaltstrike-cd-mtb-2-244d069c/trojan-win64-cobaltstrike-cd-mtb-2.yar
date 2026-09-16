rule Trojan_Win64_CobaltStrike_CD_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.CD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 89 c0 41 c1 f8 1f 44 29 c2 44 6b c2 ?? 44 29 c0 89 c2 89 d0 83 c0 ?? 31 c1 48 8b 95 ?? ?? 00 00 8b 85 ?? ?? 00 00 48 98 88 0c 02 83 85 ?? ?? 00 00 01 eb } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}