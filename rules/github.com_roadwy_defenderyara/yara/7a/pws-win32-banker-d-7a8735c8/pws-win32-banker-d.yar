rule PWS_Win32_Banker_D{
	meta:
		description = "PWS:Win32/Banker.D,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 61 6e 74 61 6e 64 65 72 } 		$a_01_1 = {47 65 74 4d 6f 6e 69 74 6f 72 49 6e 66 6f } 		$a_01_2 = {41 75 74 6f 43 6f 6e 6e 65 63 74 40 49 48 } 		$a_01_3 = {69 6e 66 65 63 74 2e 70 68 70 } 		$a_03_4 = {35 ae ca 7b c3 ff 25 ?? ?? ?? ?? 8b c0 53 33 db 6a 00 e8 ee ff ff ff 83 f8 07 75 1c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_03_4  & 1)*2) >=5
 
}