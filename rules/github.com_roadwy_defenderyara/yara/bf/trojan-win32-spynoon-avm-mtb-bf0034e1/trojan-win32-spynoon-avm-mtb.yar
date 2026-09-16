rule Trojan_Win32_Spynoon_AVM_MTB{
	meta:
		description = "Trojan:Win32/Spynoon.AVM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {48 79 76 6b 66 63 6f 72 66 } 		$a_01_1 = {53 00 48 00 4c 00 57 00 41 00 50 00 49 00 2e 00 44 00 4c 00 4c 00 } 		$a_81_2 = {31 34 31 3a 31 40 31 46 31 4c 31 52 31 58 31 } 		$a_81_3 = {31 64 31 6a 31 70 31 76 31 7c 31 } 	condition:
		((#a_81_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}