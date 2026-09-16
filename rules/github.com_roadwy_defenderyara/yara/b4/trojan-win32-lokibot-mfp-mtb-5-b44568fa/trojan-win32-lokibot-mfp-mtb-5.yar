rule Trojan_Win32_Lokibot_MFP_MTB_5{
	meta:
		description = "Trojan:Win32/Lokibot.MFP!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {30 17 5e 1b 03 24 e2 67 dd 4d a2 67 30 41 0c fd b1 55 51 89 8d b1 0c 22 5c c2 df 2c ab 98 f4 ed ee 89 ef a7 29 b0 5b 3c 8b e9 a7 9e 19 cb a0 a6 ce 73 76 e6 55 d6 34 08 fe 34 19 52 75 13 fe d4 7c af ef 1d 3b 92 04 d3 1d f3 69 6e 21 64 6c 1c 59 76 9c 27 6d ad 5f 09 b6 0c 36 7f b0 10 d4 95 e8 a6 06 e4 90 c7 99 09 75 91 80 7a 41 d2 41 18 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}