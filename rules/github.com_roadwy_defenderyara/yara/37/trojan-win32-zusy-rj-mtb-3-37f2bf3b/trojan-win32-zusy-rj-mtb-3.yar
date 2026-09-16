rule Trojan_Win32_Zusy_RJ_MTB_3{
	meta:
		description = "Trojan:Win32/Zusy.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 14 8d 54 24 10 8b c1 c1 e8 03 c1 e1 05 0b c1 f7 d0 89 44 24 14 } 		$a_01_1 = {33 34 66 34 62 63 62 63 64 34 39 63 37 63 64 34 36 63 38 65 38 63 38 34 39 36 62 34 37 63 38 65 38 34 36 63 63 34 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}