rule Ransom_Win32_GandCrab_AD_MTB_2{
	meta:
		description = "Ransom:Win32/GandCrab.AD!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {64 61 6c 61 74 65 62 69 6a 61 79 75 63 6f 67 75 7a 65 6e 75 6b 6f 77 6f 77 61 77 6f 73 61 73 69 79 6f 7a 69 77 69 77 61 63 75 6d 6f } 		$a_01_1 = {53 61 73 65 76 75 6a 69 } 		$a_01_2 = {66 00 72 00 61 00 6d 00 69 00 66 00 6f 00 6d 00 6f 00 78 00 61 00 76 00 6f 00 6b 00 61 00 72 00 75 00 6e 00 65 00 6e 00 6f 00 79 00 69 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}