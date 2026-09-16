rule Trojan_Win64_CobaltStrike_CK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 8b d0 48 8d 49 ?? 83 e2 ?? 49 ff c0 0f b6 04 3a 32 44 0b ?? 88 41 ?? 49 83 e9 ?? 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}