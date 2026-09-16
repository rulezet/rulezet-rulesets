rule Trojan_Win32_Ursnif_MTB_4{
	meta:
		description = "Trojan:Win32/Ursnif!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c1 89 7d 00 0f b7 2d ?? ?? ?? ?? 03 c0 2b c5 83 e8 ?? ff 4c 24 ?? 0f 85 ?? ?? ff ff 90 0a 40 00 8b 6c 24 ?? 83 44 24 ?? ?? 8d 04 ?? 81 c7 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}