rule Trojan_Win32_Qbot_RPY_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 45 f0 0f b6 08 3a db 74 40 bb 08 00 00 00 53 3a db 74 4e 03 45 f0 88 08 e9 b8 01 00 00 } 		$a_01_1 = {5e f7 f6 66 3b c0 74 c2 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}