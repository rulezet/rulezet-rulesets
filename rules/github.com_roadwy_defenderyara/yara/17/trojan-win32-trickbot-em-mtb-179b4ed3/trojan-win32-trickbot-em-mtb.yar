rule Trojan_Win32_Trickbot_EM_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be c8 81 e1 ?? ?? ?? ?? 8b c1 c1 e8 03 83 e1 07 8d 14 30 b0 01 d2 e0 8d 7f 01 08 02 8a 07 84 c0 75 dd } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}