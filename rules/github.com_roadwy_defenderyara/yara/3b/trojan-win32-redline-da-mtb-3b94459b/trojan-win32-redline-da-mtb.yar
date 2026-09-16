rule Trojan_Win32_Redline_DA_MTB{
	meta:
		description = "Trojan:Win32/Redline.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {83 c4 04 80 04 1f } 		$a_01_1 = {83 c4 04 80 34 1f } 		$a_03_2 = {83 c4 04 80 34 1f ?? 43 39 de 0f 85 } 		$a_01_3 = {78 62 79 75 69 64 67 41 59 55 37 75 69 6b 6a } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}