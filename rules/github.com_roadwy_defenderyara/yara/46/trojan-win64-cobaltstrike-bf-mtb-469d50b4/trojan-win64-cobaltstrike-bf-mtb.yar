rule Trojan_Win64_CobaltStrike_BF_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 8a 4c 04 ?? 8b 74 24 ?? 44 89 c9 44 30 c1 40 20 f1 44 30 c6 44 20 ce 40 08 ce 40 88 74 04 ?? 49 ff c2 48 ff c0 48 83 f8 ?? 75 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}