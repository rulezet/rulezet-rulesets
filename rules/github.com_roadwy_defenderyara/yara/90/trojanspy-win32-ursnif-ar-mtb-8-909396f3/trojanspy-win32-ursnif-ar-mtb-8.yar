rule TrojanSpy_Win32_Ursnif_AR_MTB_8{
	meta:
		description = "TrojanSpy:Win32/Ursnif.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {05 00 50 0a 00 89 85 04 ff ff ff 8b 85 60 ff ff ff 03 45 c4 0f b7 4d cc 03 c1 66 89 85 ?? ?? ?? ?? 8b 45 9c 03 45 ec 03 45 e4 89 45 c8 83 65 ?? ?? eb } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}