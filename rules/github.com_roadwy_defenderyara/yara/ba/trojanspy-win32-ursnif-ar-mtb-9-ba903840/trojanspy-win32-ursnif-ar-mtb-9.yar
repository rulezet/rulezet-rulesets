rule TrojanSpy_Win32_Ursnif_AR_MTB_9{
	meta:
		description = "TrojanSpy:Win32/Ursnif.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {81 c7 cc f7 e5 01 03 c3 8d 94 08 67 da ff ff 89 7d 00 0f b7 0d ?? ?? ?? ?? 0f af c9 81 f9 d3 7a 00 00 } 		$a_00_1 = {8b f9 2b fd 05 5c 03 0d 01 83 c7 08 ff 4c 24 18 89 02 } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}