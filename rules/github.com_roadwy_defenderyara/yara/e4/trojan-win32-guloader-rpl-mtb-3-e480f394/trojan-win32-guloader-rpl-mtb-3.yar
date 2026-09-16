rule Trojan_Win32_Guloader_RPL_MTB_3{
	meta:
		description = "Trojan:Win32/Guloader.RPL!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 0c 30 0f ae e8 de cb eb 4b } 		$a_01_1 = {9b 66 0f 61 d9 d8 d4 eb 48 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}