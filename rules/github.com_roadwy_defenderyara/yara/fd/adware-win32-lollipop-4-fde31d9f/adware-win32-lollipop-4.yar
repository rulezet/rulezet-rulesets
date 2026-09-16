rule Adware_Win32_Lollipop_4{
	meta:
		description = "Adware:Win32/Lollipop,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 "
		
	strings :
		$a_03_0 = {46 33 db 3b f2 0f 9c c3 f6 c3 ?? 75 } 		$a_01_1 = {3f 41 56 44 6f 67 40 40 } 		$a_01_2 = {3f 41 56 4d 61 6d 6d 61 6c 40 40 } 		$a_01_3 = {3f 41 56 41 6e 69 6d 61 6c 40 40 } 		$a_01_4 = {3f 41 56 43 61 74 40 40 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=12
 
}