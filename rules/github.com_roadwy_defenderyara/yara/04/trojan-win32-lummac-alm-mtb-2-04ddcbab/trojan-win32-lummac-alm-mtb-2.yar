rule Trojan_Win32_LummaC_ALM_MTB_2{
	meta:
		description = "Trojan:Win32/LummaC.ALM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 ce f7 d6 89 c8 c1 e8 02 83 e6 02 0f af f0 c0 e0 02 0c 02 88 cc d0 ec 80 e4 01 f6 e4 00 c0 88 dc 80 e4 fc 28 e0 04 94 0f b6 f8 8d 04 b1 01 f8 04 02 32 04 0c 04 12 88 04 0c 41 83 c3 02 83 f9 08 } 		$a_01_1 = {89 c1 80 c1 5d 32 0c 02 80 c1 2f 88 0c 02 40 83 f8 1a } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}