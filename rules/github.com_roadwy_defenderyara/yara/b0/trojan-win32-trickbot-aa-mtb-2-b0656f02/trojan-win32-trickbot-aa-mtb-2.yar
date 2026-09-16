rule Trojan_Win32_Trickbot_AA_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {b9 56 01 00 00 f7 f9 bf 56 01 00 00 0f b6 ea 0f b6 04 2e 8d 0c 2e 03 c3 88 54 24 12 99 f7 ff 0f b6 da 03 f3 8b c6 88 54 24 13 e8 ?? ?? ?? ?? 0f b6 01 0f b6 16 03 c2 99 8b cf f7 f9 88 54 24 11 } 		$a_00_1 = {8a 0c 32 8b 7c 24 1c 30 0c 38 40 3b 44 24 20 89 44 24 14 } 	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}