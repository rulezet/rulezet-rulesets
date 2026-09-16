rule TrojanSpy_Win32_Ursnif_AR_MTB_13{
	meta:
		description = "TrojanSpy:Win32/Ursnif.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_00_0 = {89 55 f4 89 4d fc b8 07 00 00 00 01 45 f8 8b 45 fc 8b 08 2b 4d f4 8b 55 fc 89 0a 8b e5 5d } 		$a_02_1 = {39 55 b0 73 40 a1 ?? ?? ?? 00 89 45 80 b8 f9 cd 03 00 01 45 80 83 7d b0 00 7c } 	condition:
		((#a_00_0  & 1)*2+(#a_02_1  & 1)*2) >=4
 
}