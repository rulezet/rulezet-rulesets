rule Trojan_Win64_CobaltStrike_SP_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 8b d0 c1 ea 08 88 14 01 [0-70] 41 03 c2 09 43 ?? 89 8b ?? 00 00 00 8d 81 ?? ?? ?? ?? 09 43 ?? 49 81 f9 ?? ?? ?? 00 0f 8c ?? ff ff ff } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}