rule Trojan_Win32_Silentbanker_B{
	meta:
		description = "Trojan:Win32/Silentbanker.B,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 83 ec 54 53 56 57 6a 06 59 be ?? ?? ?? ?? 8d 7d e4 f3 a5 66 a5 a4 6a 06 59 be ?? ?? ?? ?? 8d 7d c8 f3 a5 8b 5d 08 66 a5 a4 6a 06 59 be ?? ?? ?? ?? 8d 7d ac f3 a5 66 a5 8d 45 e4 53 50 a4 e8 ?? ?? ff ff 85 c0 59 59 74 14 8d 4d e4 2b c1 83 c0 ?? 99 6a 1a 59 f7 f9 8a 44 15 e4 eb 4a } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}