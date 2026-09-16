rule Backdoor_Win32_Kotu{
	meta:
		description = "Backdoor:Win32/Kotu,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {be 22 00 00 00 f7 f6 0f be 92 ?? ?? ?? ?? 33 ca 8b 85 d0 fc ff ff 88 8c 05 e0 fd ff ff eb af } 		$a_01_1 = {68 64 66 6b 6a 67 68 66 64 73 67 73 75 65 72 79 69 00 } 		$a_01_2 = {71 71 61 00 25 75 00 } 		$a_03_3 = {52 61 73 44 69 61 6c 45 76 65 6e 74 [0-07] 4e 65 77 [0-07] 6d 6f 64 65 6d [0-10] 63 61 62 6c 65 } 	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=5
 
}