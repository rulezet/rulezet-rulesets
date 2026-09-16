rule Trojan_Win32_Fareit_SM_MTB_2{
	meta:
		description = "Trojan:Win32/Fareit.SM!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 46 04 8b 16 01 d8 01 da e8 76 1e 00 00 83 c6 08 4f 75 ec } 		$a_01_1 = {8b 55 f0 88 02 90 90 90 90 ff 45 ec ff 4d dc 0f 85 5a fe ff ff } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}