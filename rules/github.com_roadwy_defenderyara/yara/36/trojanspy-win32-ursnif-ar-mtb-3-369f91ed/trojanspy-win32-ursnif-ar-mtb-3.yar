rule TrojanSpy_Win32_Ursnif_AR_MTB_3{
	meta:
		description = "TrojanSpy:Win32/Ursnif.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {05 20 da 0f 01 a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 4d e8 8b 15 ?? ?? ?? ?? 89 91 7d e2 ff ff } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}