rule Trojan_Win32_IRCBot_RTH_MTB{
	meta:
		description = "Trojan:Win32/IRCBot.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {68 ec 09 71 00 5e 4f e8 ?? ?? ?? ?? 29 df 4b 21 df 31 30 09 fb bf df 93 9e 8c 81 c0 01 00 00 00 29 fb 83 ec 04 89 3c 24 5f 81 c3 74 c0 53 5c 39 c8 75 } 		$a_02_1 = {bf 2e ce 43 00 21 c0 e8 ?? ?? ?? ?? 09 c3 b8 c4 9c da 43 31 3e 81 e8 50 cd 61 97 29 db 81 c6 01 00 00 00 39 ce 75 } 		$a_02_2 = {68 2e ce 43 00 5b 21 f1 e8 ?? ?? ?? ?? 01 f1 31 1a 89 ce 29 f6 42 39 fa 75 } 	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2+(#a_02_2  & 1)*2) >=2
 
}