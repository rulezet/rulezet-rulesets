rule TrojanSpy_Win32_Ursnif_AR_MTB_5{
	meta:
		description = "TrojanSpy:Win32/Ursnif.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 7c 24 10 03 d0 8b 44 24 14 05 20 6b 00 01 89 44 24 14 a3 ?? ?? ?? ?? 89 07 39 15 ?? ?? ?? ?? 77 13 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}