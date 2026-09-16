rule Trojan_Win32_Ursnif_MTB_5{
	meta:
		description = "Trojan:Win32/Ursnif!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b7 c1 2b c6 8d 58 ?? 2b d9 81 eb ?? ?? ?? ?? 0f b7 cb 81 c7 ?? ?? ?? ?? 8b d9 03 5c 24 ?? 89 7d 00 8b 6c 24 10 83 c5 04 ff 4c 24 14 8d 9c 43 ?? ?? ?? ?? 89 1d ?? ?? ?? ?? 89 6c 24 10 0f 85 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}