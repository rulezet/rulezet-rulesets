rule Trojan_BAT_PsDownload_MA_MTB{
	meta:
		description = "Trojan:BAT/PsDownload.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {13 04 11 04 07 16 07 8e 69 6f ?? ?? ?? 0a 13 05 09 6f ?? ?? ?? 0a 00 28 ?? ?? ?? 0a 11 05 6f ?? ?? ?? 0a 13 07 2b 00 11 07 2a } 		$a_01_1 = {45 45 2d 39 31 32 52 65 62 6f 6f 74 52 65 6d 69 6e 64 65 72 2e 73 63 72 69 70 74 2e 70 73 31 } 		$a_01_2 = {57 72 69 74 65 52 65 73 6f 75 72 63 65 54 6f 46 69 6c 65 } 		$a_01_3 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}