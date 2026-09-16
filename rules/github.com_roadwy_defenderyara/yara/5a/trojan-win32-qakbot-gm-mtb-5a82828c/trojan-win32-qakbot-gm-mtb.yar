rule Trojan_Win32_Qakbot_GM_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {b8 0e 00 00 00 ff 35 ?? ?? ?? ?? b8 9c 00 00 00 ff 35 ?? ?? ?? ?? b8 11 00 00 00 ff 35 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? b8 01 00 00 00 50 ff 25 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}