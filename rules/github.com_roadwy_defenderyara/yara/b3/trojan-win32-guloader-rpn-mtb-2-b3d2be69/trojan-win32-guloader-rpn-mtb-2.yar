rule Trojan_Win32_Guloader_RPN_MTB_2{
	meta:
		description = "Trojan:Win32/Guloader.RPN!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 1c 0e 81 f9 bd 00 00 00 81 fa 98 00 00 00 09 1c 08 83 fa 40 81 f9 cc 00 00 00 31 3c 08 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}