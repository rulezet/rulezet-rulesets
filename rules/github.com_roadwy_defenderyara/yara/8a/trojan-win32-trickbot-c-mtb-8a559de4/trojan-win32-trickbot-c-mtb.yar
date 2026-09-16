rule Trojan_Win32_Trickbot_C_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 ef 01 89 5d e0 01 fb 8b 7d e0 0f af fb 83 e7 01 83 ff 00 0f 94 c3 80 e3 01 88 5d ee } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}