rule Trojan_Win32_KeyLogger_BE_MTB_2{
	meta:
		description = "Trojan:Win32/KeyLogger.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {10 8a 85 55 28 2a 3d fb fc fa a0 68 10 a7 38 08 00 2b 33 71 b5 21 3d fb fc fa a0 68 10 a7 38 08 00 2b 33 71 b5 43 6c 61 73 } 		$a_01_1 = {05 4f 9a c3 ec bd 05 f0 3e 8e 3a 4f ad 33 99 66 cf 11 b7 0c 00 aa 00 60 d3 93 46 6f 72 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}