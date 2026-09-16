rule Trojan_Win32_Qakbot_AL_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.AL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 02 8b 45 ?? 2d 80 0d 00 00 03 45 ?? 89 45 ?? 8b 45 ?? 03 45 ?? 8b 55 ?? 31 02 [0-20] e8 90 0a 40 00 8b 45 ?? 8b 55 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}