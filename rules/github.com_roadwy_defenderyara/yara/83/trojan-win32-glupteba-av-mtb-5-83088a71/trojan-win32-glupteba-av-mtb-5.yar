rule Trojan_Win32_Glupteba_AV_MTB_5{
	meta:
		description = "Trojan:Win32/Glupteba.AV!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d cc 6b 84 00 75 03 83 c1 15 40 3d 45 74 8d 00 7c ee } 		$a_01_1 = {30 04 33 83 ff 19 75 2e 6a 00 8d 44 24 10 50 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}