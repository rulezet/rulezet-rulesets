rule Trojan_Win32_Qakbot_GB_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 02 88 01 8b 4d ?? 83 c1 01 89 4d ?? 8b 55 ?? 83 c2 01 89 55 ?? 8b 45 ?? 2d 44 49 00 00 03 45 fc 2b 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 c8 89 0d ?? ?? ?? ?? c7 45 ?? 01 00 00 00 eb } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}