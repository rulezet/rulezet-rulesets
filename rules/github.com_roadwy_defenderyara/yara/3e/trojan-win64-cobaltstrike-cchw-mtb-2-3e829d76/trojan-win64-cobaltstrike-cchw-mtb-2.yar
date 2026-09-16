rule Trojan_Win64_CobaltStrike_CCHW_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCHW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 6d 00 31 c0 31 c9 31 d2 31 db eb 0f 41 83 f1 ?? 45 88 4c 18 ff 48 ff c0 4c 89 c1 48 3d } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}