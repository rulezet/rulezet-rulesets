rule TrojanSpy_Win32_Ursnif_AR_MTB_2{
	meta:
		description = "TrojanSpy:Win32/Ursnif.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 c1 1c 4f 8d 01 03 ff 81 7c 24 1c 8d c7 00 00 89 4c 24 14 89 0d ?? ?? ?? ?? 89 08 75 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}