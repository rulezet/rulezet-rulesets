rule Trojan_Win32_Fareit_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/Fareit.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {88 07 90 90 b0 29 90 90 30 07 8a 07 90 90 90 e8 } 		$a_01_1 = {90 90 43 81 fb 07 5d 00 00 75 b7 81 c6 34 08 00 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}