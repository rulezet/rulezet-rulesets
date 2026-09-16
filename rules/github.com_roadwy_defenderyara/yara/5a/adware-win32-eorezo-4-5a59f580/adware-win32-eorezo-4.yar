rule Adware_Win32_Eorezo_4{
	meta:
		description = "Adware:Win32/Eorezo,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8a 04 31 bf 00 01 00 00 2c ?? 0f be c0 99 f7 ff 88 14 31 41 3b 4d 08 7c ?? 56 e8 ?? ?? ?? ?? 59 50 56 8d 4d e0 ff 15 } 		$a_01_1 = {59 32 68 76 59 32 38 3d } 		$a_01_2 = {50 41 55 53 45 00 00 00 55 70 64 61 74 65 20 44 6f 6e 65 20 53 75 63 63 65 73 73 66 75 6c 6c 79 00 } 		$a_01_3 = {74 80 80 7c 46 3b 3b 6d 70 7f 3a 7e } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}