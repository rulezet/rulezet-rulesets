rule Trojan_Win32_Zbot_RE_MTB{
	meta:
		description = "Trojan:Win32/Zbot.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2a 40 00 64 2a 40 00 58 2a 40 00 4c 2a 40 00 40 2a 40 00 34 2a 40 00 20 2a 40 00 14 2a 40 00 0c 2a } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}