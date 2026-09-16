rule Trojan_Win32_Zbot_RT_MTB{
	meta:
		description = "Trojan:Win32/Zbot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 18 8b 45 ?? 05 8a a5 08 00 03 45 ?? 8b 55 ?? 31 02 8d 85 ?? ?? ?? ?? 33 c9 ba [0-04] e8 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 33 c9 ba } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}