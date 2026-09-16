rule TrojanSpy_Win32_Ursnif_AR_MTB_6{
	meta:
		description = "TrojanSpy:Win32/Ursnif.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 0e 8b f3 6b c8 51 2b f1 8b 4c 24 0c 2b c8 81 c6 9b 54 00 00 8d 81 ?? ?? ?? ?? 8b 4c 24 10 83 c1 04 89 4c 24 10 81 f9 ?? ?? ?? ?? 8b 4c 24 14 0f } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}