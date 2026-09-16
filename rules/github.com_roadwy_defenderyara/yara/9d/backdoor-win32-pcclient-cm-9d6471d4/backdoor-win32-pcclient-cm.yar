rule Backdoor_Win32_PcClient_CM{
	meta:
		description = "Backdoor:Win32/PcClient.CM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {3b d3 76 2e bf ?? ?? ?? ?? 81 3c 01 ?? ?? ?? ?? 75 06 39 7c 01 04 74 07 41 3b ca 72 ec eb 13 } 		$a_01_1 = {2b f0 8a 14 06 8a 18 3a d3 75 11 41 40 3b cf 7c f1 } 		$a_03_2 = {76 12 80 3c 38 0d 74 13 47 8b cb 2b cf 83 e9 ?? 3b f9 72 ee 47 3b fb 72 ac eb 3a } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}