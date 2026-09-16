rule Trojan_Win32_Zbot_BAA_MTB{
	meta:
		description = "Trojan:Win32/Zbot.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 94 06 32 09 00 00 88 14 08 8b 7c 24 10 40 3b c7 72 } 	condition:
		((#a_01_0  & 1)*3) >=3
 
}