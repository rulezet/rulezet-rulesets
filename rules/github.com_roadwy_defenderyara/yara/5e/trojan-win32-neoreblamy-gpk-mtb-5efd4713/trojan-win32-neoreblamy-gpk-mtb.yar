rule Trojan_Win32_Neoreblamy_GPK_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.GPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {eb 07 8b 45 ?? 40 89 45 90 1b 00 83 7d 90 1b 00 ?? 7f 28 6b 45 90 1b 00 ?? 8d 84 05 ?? ?? ?? ?? 8b 4d 90 1b 00 8b 55 90 1b 00 42 42 6b d2 18 8d 94 15 ?? ?? ?? ?? 8b 75 90 1b 00 8b 04 88 89 04 b2 eb cb 8b 45 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}