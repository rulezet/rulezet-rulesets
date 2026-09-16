rule TrojanSpy_Win32_Ursnif_AR_MTB{
	meta:
		description = "TrojanSpy:Win32/Ursnif.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 c2 8c a6 44 01 2b c8 89 15 ?? ?? ?? ?? 2b cb 03 f1 8b 4c 24 10 89 11 8b ce 2b c8 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}