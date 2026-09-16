rule Trojan_Win32_Guloader_RPN_MTB_3{
	meta:
		description = "Trojan:Win32/Guloader.RPN!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {ff 55 08 66 0f 66 ca 0f d8 c3 0f 6b fc eb 11 } 		$a_01_1 = {31 0c 06 66 0f 69 c6 9b db e2 66 0f 69 cf eb 0f } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}