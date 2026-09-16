rule TrojanSpy_Win32_Ursnif_GKM_MTB_4{
	meta:
		description = "TrojanSpy:Win32/Ursnif.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c9 6b c9 34 2a d9 8a ca f6 d8 c0 e1 06 02 ca 2a c1 02 d8 8b 44 24 ?? 05 70 80 06 01 a3 ?? ?? ?? ?? 89 84 3d ?? ?? ?? ?? 83 c7 04 8b 15 ?? ?? ?? ?? 0f b6 c3 66 83 e8 1c 66 03 c2 0f b7 c8 89 4c 24 ?? 81 ff 63 19 00 00 73 ?? a1 ?? ?? ?? ?? e9 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}