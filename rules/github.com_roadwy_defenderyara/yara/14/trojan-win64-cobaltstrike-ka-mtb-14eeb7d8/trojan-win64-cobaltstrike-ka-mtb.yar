rule Trojan_Win64_CobaltStrike_KA_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 8b c8 41 8b d2 d3 ea 8a 08 48 8b 47 ?? 80 f1 ?? 22 d1 48 63 8f ?? ?? ?? ?? 88 14 01 ff 87 ?? ?? ?? ?? 45 85 c0 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}