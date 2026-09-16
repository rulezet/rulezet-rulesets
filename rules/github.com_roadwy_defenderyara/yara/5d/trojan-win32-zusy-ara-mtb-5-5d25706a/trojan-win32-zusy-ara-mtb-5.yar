rule Trojan_Win32_Zusy_ARA_MTB_5{
	meta:
		description = "Trojan:Win32/Zusy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {32 d1 41 81 e1 ff 00 00 80 88 94 05 60 fd ff ff 79 08 49 81 c9 00 ff ff ff 41 40 83 f8 ?? 7c da } 		$a_01_1 = {8a 84 0f 74 24 a6 b2 32 c2 42 81 e2 ff 00 00 80 88 04 31 79 08 4a 81 ca 00 ff ff ff 42 41 83 f9 0e 7c dd } 		$a_80_2 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_80_2  & 1)*1) >=3
 
}