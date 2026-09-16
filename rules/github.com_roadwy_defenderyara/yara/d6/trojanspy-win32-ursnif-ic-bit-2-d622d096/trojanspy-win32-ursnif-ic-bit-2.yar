rule TrojanSpy_Win32_Ursnif_IC_bit_2{
	meta:
		description = "TrojanSpy:Win32/Ursnif.IC!bit,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b 0a 83 c1 01 81 e1 fe 00 00 00 ff 34 ca e2 fb } 		$a_03_1 = {8a 0e 0f b6 d0 0f b6 c9 33 d1 83 e2 0f c1 e8 04 33 04 95 ?? ?? ?? ?? c1 e9 04 8b d0 83 e2 0f 4f 33 ca c1 e8 04 46 33 04 8d } 		$a_03_2 = {8b 10 3b 55 ?? 75 0a 8b 50 04 3b 55 ?? 75 02 8b d8 83 c0 28 49 74 04 85 db 74 e5 } 		$a_03_3 = {68 c8 04 00 00 50 89 44 24 28 89 44 24 2c 8d 44 24 30 50 83 cb ff c7 44 24 28 eb fe cc cc e8 ?? ?? ?? ?? 83 c4 0c e8 ?? ?? ?? ?? 8b f0 8d 44 24 08 50 ff 37 } 		$a_03_4 = {2b ca 2b ce 81 c1 ?? ?? ?? ?? 8b 41 04 2b 41 0c 03 01 3d } 	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=12
 
}