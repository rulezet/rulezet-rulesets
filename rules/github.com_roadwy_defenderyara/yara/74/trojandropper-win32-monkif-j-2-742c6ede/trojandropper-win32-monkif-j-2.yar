rule TrojanDropper_Win32_Monkif_J_2{
	meta:
		description = "TrojanDropper:Win32/Monkif.J,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 74 24 0c 2b f7 8a 84 16 ?? ?? ?? ?? 2a c2 2c 4f 88 82 ?? ?? ?? ?? 42 3b 54 24 10 7c } 		$a_03_1 = {50 68 01 00 00 80 ff 55 f4 85 c0 75 3e ff 75 08 ff d6 50 ff 75 08 6a 01 53 53 ff 75 fc ff 55 f8 85 c0 75 27 bf ?? ?? ?? ?? 57 ff d6 50 57 6a 01 53 68 ?? ?? ?? ?? ff 75 fc ff 55 f8 85 c0 75 0b ff 75 fc ff 55 f0 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}