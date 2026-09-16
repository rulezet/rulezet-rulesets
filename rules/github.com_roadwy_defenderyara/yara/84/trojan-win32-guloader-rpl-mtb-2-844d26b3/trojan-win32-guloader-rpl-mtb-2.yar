rule Trojan_Win32_Guloader_RPL_MTB_2{
	meta:
		description = "Trojan:Win32/Guloader.RPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 2c 17 f7 c2 [0-20] 90 13 [0-20] 90 13 [0-10] 81 f5 [0-20] 90 13 [0-20] 90 13 [0-10] 01 2c 10 [0-20] 90 13 [0-20] 90 13 [0-20] 90 13 83 da 04 0f 8d } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}