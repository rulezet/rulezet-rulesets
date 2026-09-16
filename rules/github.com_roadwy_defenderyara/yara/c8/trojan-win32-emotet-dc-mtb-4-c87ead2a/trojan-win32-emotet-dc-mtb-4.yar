rule Trojan_Win32_Emotet_DC_MTB_4{
	meta:
		description = "Trojan:Win32/Emotet.DC!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 c4 04 0d 00 10 00 00 50 68 00 4e 02 00 57 6a ff } 		$a_01_1 = {83 c4 04 0d 00 10 00 00 50 68 00 4e 02 00 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}