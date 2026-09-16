rule Trojan_Win32_Zusy_AZY_MTB_3{
	meta:
		description = "Trojan:Win32/Zusy.AZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {bf 02 9f f5 24 bb 16 27 1a 3f bd 2c 25 34 b6 8b 4c 24 24 81 f9 01 9f f5 24 7f 61 81 f9 6a d2 00 e1 0f 8e a7 00 00 00 81 f9 1d 08 72 f8 0f 8f 42 01 00 00 81 f9 6b d2 00 e1 0f 84 0a 02 00 00 81 f9 1f 1f dd e5 0f 84 3d 02 00 00 81 f9 38 08 97 f5 } 		$a_01_1 = {8b 4c 24 14 8a 54 24 0b 80 c2 34 88 54 01 30 8b 4c 24 14 8a 54 24 0b 80 c2 35 88 54 01 31 8b 0c 24 c7 01 1f 1f dd e5 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}