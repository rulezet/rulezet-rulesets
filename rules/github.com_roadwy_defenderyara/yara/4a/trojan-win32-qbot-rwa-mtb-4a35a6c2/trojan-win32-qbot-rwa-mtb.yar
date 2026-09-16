rule Trojan_Win32_Qbot_RWA_MTB{
	meta:
		description = "Trojan:Win32/Qbot.RWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {05 8a a5 08 00 03 45 ?? 8b 15 ?? ?? ?? ?? 31 02 a1 ?? ?? ?? ?? 83 c0 04 a3 ?? ?? ?? ?? 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}