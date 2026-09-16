rule Trojan_Win32_Qakbot_EA_MTB_5{
	meta:
		description = "Trojan:Win32/Qakbot.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {2a c1 88 44 35 ec 46 83 fe 04 7c d9 8b 45 ec 8a ec 8a 55 ee 8a c8 83 45 e0 03 8a c4 c0 e1 02 c0 ed 04 80 e5 03 c0 e0 04 02 e9 } 		$a_01_1 = {64 66 78 73 67 64 66 68 64 67 66 6a 68 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}