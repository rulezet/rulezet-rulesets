rule Trojan_Win64_CobaltStrike_MW_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 63 d8 48 69 f3 ?? ?? ?? ?? 48 89 f1 48 c1 e9 ?? 48 c1 fe ?? 01 ce c1 e6 ?? 8d 0c b6 29 cb 48 63 cb 42 0f b6 0c 01 32 0c 02 88 0c 07 48 ff c0 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}