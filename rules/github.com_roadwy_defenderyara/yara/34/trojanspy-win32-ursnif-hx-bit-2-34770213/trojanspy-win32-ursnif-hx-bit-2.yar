rule TrojanSpy_Win32_Ursnif_HX_bit_2{
	meta:
		description = "TrojanSpy:Win32/Ursnif.HX!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {8d 04 11 33 45 d8 83 e6 1f 33 45 dc } 		$a_01_1 = {43 8a cb d3 c0 33 c6 33 44 24 10 8b f0 89 32 } 		$a_03_2 = {8b 08 69 c9 ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 89 0a 69 c9 ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 56 66 8b f1 69 c9 ?? ?? ?? ?? 66 89 72 04 be ?? ?? ?? ?? 03 ce 57 89 08 66 89 4a 06 33 ff } 		$a_03_3 = {8b 08 69 c9 ?? ?? ?? ?? 03 ce 88 4c 3a 08 47 89 08 83 ff 08 72 ea } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}