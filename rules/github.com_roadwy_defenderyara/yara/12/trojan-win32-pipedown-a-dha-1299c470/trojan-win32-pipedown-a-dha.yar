rule Trojan_Win32_PipeDown_A_dha{
	meta:
		description = "Trojan:Win32/PipeDown.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_42_0 = {8e f8 04 00 00 0f b6 c3 8d 14 19 90 02 01 8a 04 08 30 82 00 01 00 00 90 02 01 8b 86 fc 04 00 00 90 02 06 3b d8 72 90 00 01 } 		$a_c8_1 = {00 00 8d 14 90 01 01 0f b6 cb 43 8a 04 01 30 82 90 01 04 3b 90 01 01 72 e6 90 00 00 00 78 ea 00 00 04 00 04 00 04 00 00 01 00 25 40 0f b6 01 8d 49 01 30 04 96 0f b6 41 03 30 44 95 ed 0f b6 41 07 30 } 	condition:
		((#a_42_0  & 1)*1+(#a_c8_1  & 1)*7424) >=2
 
}