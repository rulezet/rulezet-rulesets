rule Trojan_Win32_Glupteba_AV_MTB_7{
	meta:
		description = "Trojan:Win32/Glupteba.AV!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {56 83 c0 15 57 8b bc 24 f8 02 00 00 a3 } 		$a_01_1 = {30 04 33 83 ff 19 75 2e 6a 00 8d 44 24 10 } 		$a_01_2 = {8a 54 31 15 88 14 33 33 db 3d 03 02 00 00 75 19 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}