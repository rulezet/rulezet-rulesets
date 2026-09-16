rule Trojan_Win32_Qakbot_MH_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.MH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 56 4c 8b be ?? ?? ?? ?? 8d 5a 01 89 5e 4c 88 0c 17 8b 4e 4c 8b 96 ?? ?? ?? ?? 8d 79 01 89 7e 4c 88 24 0a 8b 4e 4c 8b 96 ?? ?? ?? ?? 8d 79 01 89 7e 4c 88 04 0a 8b 86 18 01 00 00 33 86 } 		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}