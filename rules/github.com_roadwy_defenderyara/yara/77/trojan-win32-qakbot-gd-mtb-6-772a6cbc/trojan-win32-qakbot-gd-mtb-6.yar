rule Trojan_Win32_Qakbot_GD_MTB_6{
	meta:
		description = "Trojan:Win32/Qakbot.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {fe c6 0f b6 f6 8a 14 3e 02 c2 0f b6 c8 88 45 0b 8a 04 39 88 04 3e 88 14 39 8a 04 3e 8b 4d f8 02 c2 0f b6 c0 8a 04 38 30 04 0b 43 8a 45 0b 3b 5d fc 7c } 		$a_01_1 = {32 04 37 88 44 3b 04 47 3b 3b } 	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}