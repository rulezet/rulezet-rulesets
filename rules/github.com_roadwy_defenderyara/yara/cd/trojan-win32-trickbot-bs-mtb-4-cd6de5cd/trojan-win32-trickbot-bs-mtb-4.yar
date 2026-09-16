rule Trojan_Win32_Trickbot_BS_MTB_4{
	meta:
		description = "Trojan:Win32/Trickbot.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {03 c2 99 f7 fb 0f b6 04 37 89 55 ?? 03 d6 8a 1a 88 1c 37 47 3b f9 88 02 7c } 		$a_00_1 = {03 d7 8a 1a 88 19 88 02 0f b6 01 0f b6 0a 03 c1 } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}