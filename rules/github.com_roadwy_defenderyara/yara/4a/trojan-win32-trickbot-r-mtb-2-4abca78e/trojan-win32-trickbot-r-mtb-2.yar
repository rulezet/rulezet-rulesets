rule Trojan_Win32_TrickBot_R_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBot.R!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {b8 db 4b 68 2f f7 e1 8b c1 2b c2 d1 e8 03 c2 c1 e8 04 6b c0 1b 8b d1 2b d0 8a 04 1a 30 04 31 83 c1 01 3b cf 75 } 		$a_01_1 = {83 ee 08 8b da 8b ce d3 fb 83 c7 01 85 f6 88 5c 07 ff 75 ec 8b 4c 24 18 83 c5 04 83 e9 01 89 4c 24 18 0f 85 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}