rule Backdoor_Win32_PcClient_ZF_2{
	meta:
		description = "Backdoor:Win32/PcClient.ZF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 fa 63 7c f6 6a 63 6a 00 8d 95 04 ff ff ff 52 e8 ?? ?? 00 00 83 c4 0c 0f be 0e 83 f9 31 75 0e 8d 85 04 ff ff ff 50 6a 63 e8 ?? ?? 00 00 0f be 16 83 fa 32 75 0e } 		$a_01_1 = {83 fa 65 0f 94 c1 0f be 50 01 83 e1 01 83 fa 78 0f 94 c0 8b 55 d4 83 e0 01 23 c8 0f be 42 02 83 f8 65 0f 94 c2 83 e2 01 23 ca 74 7d } 		$a_01_2 = {72 62 00 63 3a 5c 00 5c 53 65 74 75 70 2e 00 77 62 00 63 3a 5c 00 6f 70 65 6e } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}