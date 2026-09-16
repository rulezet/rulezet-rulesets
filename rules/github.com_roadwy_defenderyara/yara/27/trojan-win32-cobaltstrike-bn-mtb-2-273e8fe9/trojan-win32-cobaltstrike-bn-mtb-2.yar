rule Trojan_Win32_CobaltStrike_BN_MTB_2{
	meta:
		description = "Trojan:Win32/CobaltStrike.BN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 d2 03 d1 0f b6 ca 8b 55 ?? 0f b6 89 ?? ?? ?? ?? 32 0c 3a 88 0f 47 83 eb ?? 75 90 0a 30 00 0f b6 88 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}