rule Trojan_Win32_Ursnif_AD_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 44 24 14 8b 0e 8d 7c 07 bc 8b c2 0f b7 15 ?? ?? ?? 00 2b c3 05 ?? ?? ?? ?? 8b e8 69 ed ?? ?? ?? 00 81 c1 ?? ?? ?? ?? 89 0e 03 d5 83 c6 04 ff 4c 24 10 75 b4 } 		$a_02_1 = {03 ca 81 f9 ?? ?? ?? ?? 75 0d 2b d3 83 ea ?? 69 d2 ?? ?? ?? ?? 03 d0 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}