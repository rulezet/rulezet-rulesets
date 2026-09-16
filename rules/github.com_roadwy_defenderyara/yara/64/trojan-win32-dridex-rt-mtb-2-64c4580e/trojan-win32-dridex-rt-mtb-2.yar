rule Trojan_Win32_Dridex_RT_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {58 66 75 63 6b 6d 65 73 62 65 6e 55 } 		$a_81_1 = {67 31 73 68 69 74 32 61 73 74 65 73 74 65 64 2c 75 54 } 		$a_81_2 = {79 66 75 63 6b 6f 66 66 77 70 43 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}