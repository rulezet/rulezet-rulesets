rule Trojan_Win32_Guloader_AV_MTB_2{
	meta:
		description = "Trojan:Win32/Guloader.AV!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {05 01 24 0a 00 a3 } 		$a_01_1 = {01 44 24 10 8b 4c 24 10 33 cf 33 ce 2b d9 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}