rule Adware_Win32_Eorezo_7{
	meta:
		description = "Adware:Win32/Eorezo,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {39 5d 08 c6 45 fc 02 89 5d f0 7e ?? 8b 7d 0c 8b 37 56 e8 ?? ?? ?? ?? 59 50 56 ff 75 c8 8d 4d c0 53 ff 15 } 		$a_03_1 = {8a 04 31 bf 00 01 00 00 2c 0a 0f be c0 99 f7 ff 88 14 31 41 3b 4d 08 7c ?? 56 e8 ?? ?? ?? ?? 59 50 56 8d 4d e0 ff 15 ?? ?? ?? ?? 56 e8 } 		$a_00_2 = {59 32 68 76 59 32 38 3d } 		$a_00_3 = {72 7e 7e 7a 44 39 39 6b 6e 7d 38 7c 6f 71 73 6f 6e 6f 7a } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}