rule Trojan_Win32_Qbot_EB_MTB{
	meta:
		description = "Trojan:Win32/Qbot.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 d2 03 04 24 13 54 24 04 83 c4 08 } 		$a_01_1 = {29 04 24 19 54 24 04 58 5a 2b d8 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}