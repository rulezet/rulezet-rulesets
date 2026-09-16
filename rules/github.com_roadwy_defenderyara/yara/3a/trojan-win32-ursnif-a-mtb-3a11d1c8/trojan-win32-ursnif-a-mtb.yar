rule Trojan_Win32_Ursnif_A_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {04 34 02 c0 02 c2 02 44 24 14 89 44 24 18 a2 ?? ?? ?? ?? 8b 44 24 14 81 c5 9c 94 4d 01 8a 0d ?? ?? ?? ?? 0f b7 f0 8b c6 2b c3 8b 5c 24 20 83 c0 04 89 2b } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}