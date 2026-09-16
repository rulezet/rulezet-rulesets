rule Trojan_Win32_Pikabot_PA_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 c7 45 [0-02] 00 00 00 8b c6 8d 0c 1e f7 75 ?? 8a 44 15 ?? 32 04 39 46 88 01 81 fe ?? ?? ?? ?? 72 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}