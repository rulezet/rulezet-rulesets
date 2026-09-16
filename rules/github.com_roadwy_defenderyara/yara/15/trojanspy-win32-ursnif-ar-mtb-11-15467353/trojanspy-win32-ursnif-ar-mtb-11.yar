rule TrojanSpy_Win32_Ursnif_AR_MTB_11{
	meta:
		description = "TrojanSpy:Win32/Ursnif.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {05 64 9f b1 01 89 01 a3 ?? ?? ?? ?? 0f b7 05 ?? ?? ?? ?? 8d 4b d1 3b c2 76 } 		$a_02_1 = {83 44 24 10 04 81 c5 ?? ?? ?? ?? 81 7c 24 10 28 1c 00 00 89 28 0f b7 c1 8d 7c 10 06 0f 82 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}