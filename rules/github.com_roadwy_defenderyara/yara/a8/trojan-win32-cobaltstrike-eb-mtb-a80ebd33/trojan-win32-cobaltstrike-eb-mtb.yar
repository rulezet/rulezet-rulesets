rule Trojan_Win32_CobaltStrike_EB_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 1c 3e 02 1c 16 0f b6 fb 0f b6 1c 3e 8b 7d ?? 8b 75 ?? 32 1c 07 88 1c 06 40 39 45 ?? 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}