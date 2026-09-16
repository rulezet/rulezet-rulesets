rule Trojan_Win32_Qbot_DEH_MTB{
	meta:
		description = "Trojan:Win32/Qbot.DEH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {01 f9 81 e1 ff 00 00 00 8b 7c 24 34 8a 1c 0f 8b 4c 24 2c 81 e9 ?? ?? ?? ?? 8b 7c 24 28 89 0c 24 8b 4c 24 0c 8a 3c 0f 8b 0c 24 89 4c 24 48 30 fb 8b 4c 24 24 8b 7c 24 0c 88 1c 39 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}