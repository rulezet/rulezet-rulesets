rule Trojan_Win32_Dridex_EC_MTB{
	meta:
		description = "Trojan:Win32/Dridex.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {03 74 21 65 21 21 7c 6a 74 85 6a 45 04 68 57 64 63 66 6a 74 40 75 cf 68 04 74 03 21 6a 78 64 64 8b 63 6a 74 68 05 78 85 6a 20 8b 66 } 		$a_01_1 = {50 45 43 32 4e 4f } 		$a_01_2 = {67 00 6f 00 6c 00 66 00 69 00 6e 00 66 00 6f 00 2e 00 69 00 6e 00 69 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}