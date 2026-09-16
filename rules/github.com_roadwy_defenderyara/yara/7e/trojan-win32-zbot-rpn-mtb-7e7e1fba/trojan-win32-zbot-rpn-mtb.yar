rule Trojan_Win32_Zbot_RPN_MTB{
	meta:
		description = "Trojan:Win32/Zbot.RPN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 32 50 57 53 5f 56 58 ab 5f 58 83 2b 01 f7 d9 f8 19 0b ff 32 8d 52 04 8d 5b 04 59 f3 0f c9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}