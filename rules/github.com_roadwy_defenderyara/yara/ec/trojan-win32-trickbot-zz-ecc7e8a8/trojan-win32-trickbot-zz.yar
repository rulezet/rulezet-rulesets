rule Trojan_Win32_Trickbot_ZZ{
	meta:
		description = "Trojan:Win32/Trickbot.ZZ,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c0 68 1e 03 00 00 59 50 e2 fd 8b c7 57 8b ec 05 f9 24 00 00 89 45 04 8b c6 89 45 20 68 f0 ff 00 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}