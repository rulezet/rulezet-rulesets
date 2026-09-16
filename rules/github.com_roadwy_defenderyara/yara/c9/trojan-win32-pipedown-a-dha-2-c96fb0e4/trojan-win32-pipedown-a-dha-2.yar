rule Trojan_Win32_PipeDown_A_dha_2{
	meta:
		description = "Trojan:Win32/PipeDown.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_40_0 = {b6 01 8d 49 01 30 04 96 0f b6 41 03 30 44 95 ed 0f b6 41 07 30 04 93 0f b6 41 0b 30 04 97 42 83 fa 04 72 db 01 } 		$a_0f_1 = {b6 44 8d ec 8d 52 01 32 04 0e 88 44 8d ec 0f b6 44 0e 04 30 44 8d ed 0f b6 42 fb 30 44 8d ee 0f b6 42 ff 30 44 8d ef 41 83 f9 04 72 d2 01 00 21 02 43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 } 	condition:
		((#a_40_0  & 1)*1+(#a_0f_1  & 1)*11776) >=4
 
}