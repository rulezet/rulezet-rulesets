rule PWS_Win32_Ldpinch_ZT{
	meta:
		description = "PWS:Win32/Ldpinch.ZT,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {61 71 2e 71 71 2e 63 6f 6d 2f 63 6e 32 2f 66 69 6e 64 70 73 77 } 		$a_01_1 = {51 51 2e 65 78 65 } 		$a_01_2 = {54 68 65 20 42 61 74 21 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}