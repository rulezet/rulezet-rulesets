rule Trojan_Win32_IRCBot_RT_MTB_3{
	meta:
		description = "Trojan:Win32/IRCBot.RT!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 ec 09 71 00 8b 04 24 83 c4 04 01 f6 89 f1 01 ce e8 1e 00 00 00 81 ee 14 66 46 34 31 02 29 ce 21 f6 01 f6 } 		$a_01_1 = {68 ec 09 71 00 58 81 ea 15 9b 40 ff 21 db e8 28 00 00 00 21 db 31 06 09 d3 81 c6 01 00 00 00 89 d3 89 d3 21 d3 39 fe 75 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}