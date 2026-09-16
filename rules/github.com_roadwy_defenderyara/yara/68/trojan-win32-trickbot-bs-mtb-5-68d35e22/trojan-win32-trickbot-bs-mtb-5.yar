rule Trojan_Win32_Trickbot_BS_MTB_5{
	meta:
		description = "Trojan:Win32/Trickbot.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c2 99 f7 f9 8b 4c 24 ?? 33 c0 8a 04 0a 8b 54 24 ?? 0f be 0c 3a 51 50 e8 ?? ?? ?? ?? 88 07 8b 44 24 ?? 83 c4 10 47 48 89 44 24 ?? 75 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}