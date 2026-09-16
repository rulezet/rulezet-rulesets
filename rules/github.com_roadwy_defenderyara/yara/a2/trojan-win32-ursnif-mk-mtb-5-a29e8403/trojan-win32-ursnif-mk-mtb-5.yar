rule Trojan_Win32_Ursnif_MK_MTB_5{
	meta:
		description = "Trojan:Win32/Ursnif.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 33 45 0c 89 45 08 8b 4d fc 81 e9 ?? ?? ?? ?? 89 4d fc 8b 55 fc 81 c2 ?? ?? ?? ?? 89 55 fc c1 45 08 04 8b 45 fc 05 ?? ?? ?? ?? 89 45 fc 8b 45 fc 33 d2 b9 ?? ?? ?? ?? f7 f1 89 45 fc 8b 55 08 81 c2 ?? ?? ?? ?? 89 55 08 8b 45 fc 05 ?? ?? ?? ?? 89 45 fc 8b 45 08 8b e5 5d c3 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}