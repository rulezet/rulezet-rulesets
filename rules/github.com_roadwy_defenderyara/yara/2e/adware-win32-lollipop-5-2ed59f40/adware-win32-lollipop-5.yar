rule Adware_Win32_Lollipop_5{
	meta:
		description = "Adware:Win32/Lollipop,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {c7 41 18 07 00 00 00 89 ?? 14 68 90 09 06 00 6a 05 33 ?? 33 } 		$a_43_1 = {41 18 07 00 00 00 90 09 04 00 6a 05 33 90 04 01 02 d2 c0 90 00 01 } 		$a_c7_2 = {18 } 	condition:
		((#a_03_0  & 1)*1+(#a_43_1  & 1)*1+(#a_c7_2  & 1)*3840) >=3
 
}