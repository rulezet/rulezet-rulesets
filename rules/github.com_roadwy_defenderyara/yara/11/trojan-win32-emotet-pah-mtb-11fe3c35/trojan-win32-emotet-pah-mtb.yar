rule Trojan_Win32_Emotet_PAH_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {59 59 0f b6 0c 10 8b 45 ?? 0f b6 04 10 03 c8 81 e1 ?? ?? ?? ?? 79 ?? 49 83 c9 ?? 41 0f b6 c1 8b 4d ?? 8a 04 10 30 04 0e 47 8b 45 ?? 8b 55 ?? 3b 7d ?? 0f 8c ?? ?? ?? ?? 8b 7d ?? 8b 45 ?? 5e 88 5f ?? 88 07 5f 5b 8b e5 5d c3 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}