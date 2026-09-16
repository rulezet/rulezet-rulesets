rule Trojan_Win32_Razy_RPY_MTB_2{
	meta:
		description = "Trojan:Win32/Razy.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 34 81 e9 00 00 00 00 40 90 13 3b c2 90 13 0f 82 } 		$a_01_1 = {31 02 81 c2 04 00 00 00 21 fb 39 f2 75 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}