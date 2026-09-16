rule Trojan_Win32_Qakbot_AH_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {47 8d 0c 86 0f b7 c5 0f af 44 24 28 66 45 09 01 8b 44 24 14 8b 4c 24 20 31 44 24 1c 41 81 22 8d 1c 00 00 0f b7 c3 89 4c 24 20 3b c8 74 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}