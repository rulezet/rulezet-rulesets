rule Trojan_Win32_Lokibot_BC_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.BC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {b9 04 00 00 00 f7 f1 8b ?? ?? 0f be ?? ?? 8b 55 ?? 0f b6 82 ?? ?? ?? ?? 33 c1 8b 4d f8 88 81 90 1b 03 90 13 8b 55 ?? 83 c2 01 89 55 ?? 81 7d } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}