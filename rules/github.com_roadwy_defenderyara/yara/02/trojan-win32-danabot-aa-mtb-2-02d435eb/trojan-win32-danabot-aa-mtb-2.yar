rule Trojan_Win32_Danabot_AA_MTB_2{
	meta:
		description = "Trojan:Win32/Danabot.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 00 88 45 ?? 8a 45 ?? 04 9f 2c 1a 73 ?? 80 6d ?? 20 a1 ?? ?? ?? ?? 8a 00 88 45 ?? 8a 45 ?? 04 9f 2c 1a 73 ?? 80 6d ?? 20 a1 ?? ?? ?? ?? 8a 00 88 45 ?? 8a 45 ?? 04 9f 2c 1a 73 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}