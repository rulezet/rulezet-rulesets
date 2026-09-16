rule Trojan_Win32_Trickbot_SX_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f4 8b 55 0c 8d 1c 02 8b 45 f4 8b 55 0c 01 d0 8a 00 89 c6 8b 45 08 89 04 24 e8 ?? ?? ?? ?? 89 45 e4 8b 45 f4 ba 00 00 00 00 f7 75 e4 89 d1 89 ca 8b 45 08 01 d0 8a 00 31 f0 88 03 ff 45 f4 8b 45 f4 3b 45 10 0f 95 c0 84 c0 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}