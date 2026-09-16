rule Trojan_Win64_CobaltStrike_MH_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 84 24 88 00 00 00 48 8b 8c 24 b8 00 00 00 89 ca bb cd cc cc cc 48 0f af da 48 c1 eb 22 48 89 5c 24 60 48 8b 94 24 b0 00 00 00 31 f6 31 ff 45 31 c0 eb } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}