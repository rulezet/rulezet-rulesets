rule Trojan_Win32_Pikabot_RPY_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b8 ff 7f 00 00 f7 f7 31 d2 8d 78 01 89 c8 8b 0c 9e f7 f7 01 d8 8d 04 86 8b 10 89 08 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}