rule TrojanSpy_Win32_Ursnif_AR_MTB_4{
	meta:
		description = "TrojanSpy:Win32/Ursnif.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {2b d1 2b 55 d8 66 89 55 b0 8b 45 b0 0f af 45 a4 0f b7 4d c4 2b c1 88 45 [0-14] 2b c1 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}