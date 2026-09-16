rule Trojan_Win32_Spybot_RSB_MTB{
	meta:
		description = "Trojan:Win32/Spybot.RSB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {34 d7 fe c0 34 5b 04 4f 34 de fe c0 2c 7d 04 cf fe c8 34 f1 04 02 fe c0 fe c0 fe c0 fe c8 34 b7 88 84 0d ?? ?? ?? ?? 83 c1 01 eb } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}