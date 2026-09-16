rule Trojan_Win32_Ursnif_AH_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6b d2 07 03 15 ?? ?? ?? ?? 89 55 e0 8b 45 e8 83 e8 4e 2b 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 2b c8 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 2b 55 e0 83 c2 78 3b 55 f0 } 		$a_81_1 = {50 65 72 68 61 70 73 44 61 6e 63 65 2e 70 64 62 } 	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}