rule TrojanSpy_Win32_Rebhip_H{
	meta:
		description = "TrojanSpy:Win32/Rebhip.H,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b7 d6 6b fa 47 8b 53 30 8d 54 ba 20 } 		$a_01_1 = {0f b7 c6 6b c0 47 8b 53 30 8d 94 82 20 01 00 00 8b 43 30 8d 44 b8 04 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}