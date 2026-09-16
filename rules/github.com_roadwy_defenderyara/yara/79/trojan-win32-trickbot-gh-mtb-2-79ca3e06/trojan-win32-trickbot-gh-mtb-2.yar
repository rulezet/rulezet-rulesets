rule Trojan_Win32_Trickbot_GH_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 d2 09 fa 88 16 c7 45 b0 8b 00 00 00 8b bd 30 ff ff ff 8a 17 0f b6 d2 8a 1e 0f b6 db 31 d3 88 1e c7 45 ac 27 01 00 00 8a 1f 80 c3 01 88 1f c7 45 a8 df 01 00 00 8a 1e 8b 95 18 ff ff ff 8b 02 88 18 } 		$a_81_1 = {53 74 72 75 6f 4e 6f 73 57 } 	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}