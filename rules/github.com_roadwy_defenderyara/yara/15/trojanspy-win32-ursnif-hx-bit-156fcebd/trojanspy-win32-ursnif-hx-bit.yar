rule TrojanSpy_Win32_Ursnif_HX_bit{
	meta:
		description = "TrojanSpy:Win32/Ursnif.HX!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 02 85 c0 8b f0 74 ?? 33 c1 33 44 24 10 43 8a cb d3 c8 8b ce 89 02 83 c2 04 ff 4c 24 0c 75 } 		$a_01_1 = {8a cb d3 c0 33 c6 33 44 24 10 8b f0 89 32 83 c2 04 ff 4c 24 0c 75 } 		$a_03_2 = {8b 10 3b 55 ?? 75 0a 8b 50 04 3b 55 ?? 75 02 8b d8 83 c0 28 49 74 04 85 db 74 e5 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}