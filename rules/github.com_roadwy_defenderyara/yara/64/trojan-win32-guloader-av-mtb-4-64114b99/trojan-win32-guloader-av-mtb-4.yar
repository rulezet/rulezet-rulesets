rule Trojan_Win32_Guloader_AV_MTB_4{
	meta:
		description = "Trojan:Win32/Guloader.AV!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 f8 6c 75 06 81 c1 bc 2f 0a 00 40 3d 0f 7e 49 00 7c } 		$a_01_1 = {01 04 24 b8 bc 2f 0a 00 01 04 24 8b 04 24 8a 14 08 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}