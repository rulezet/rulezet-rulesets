rule Trojan_Win64_CobaltStrike_CA_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 2b ce 41 ff c0 49 03 cc 02 14 39 42 32 14 [0-02] 48 8b 0d ?? ?? ?? ?? 49 63 c6 41 ff c6 88 14 [0-02] 49 63 c9 49 3b cb 72 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}