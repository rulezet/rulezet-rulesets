rule Trojan_Win32_Qakbot_AT_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 07 0f b7 44 41 50 31 44 24 68 8b 44 24 10 8b 4c 24 44 41 89 4c 24 44 0f b6 80 82 0b 00 00 3b c8 0f 85 } 		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } 	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}