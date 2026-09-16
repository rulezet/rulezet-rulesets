rule Trojan_Win32_TrickBot_BB_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBot.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c5 99 bd f1 17 00 00 f7 fd 8b ea 8d 04 29 50 56 89 44 24 ?? e8 ?? ?? ?? ?? 8b 54 24 ?? 0f b6 0a 0f b6 06 03 c1 99 b9 f1 17 00 00 f7 f9 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}