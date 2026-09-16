rule Trojan_Win32_Qbot_DEH_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.DEH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f af ca 89 4c 24 1c 8b 4c 24 14 8a 1c 01 8b 74 24 10 88 1c 06 8b 7c 24 1c 81 f7 [0-08] 89 7c 24 1c 31 ff b9 ?? ?? ?? ?? 8b 54 24 08 29 d1 8b 54 24 0c 19 d7 89 7c 24 24 89 4c 24 20 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}