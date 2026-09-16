rule Trojan_Win32_Qbot_PAL_MTB{
	meta:
		description = "Trojan:Win32/Qbot.PAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d0 8b 45 ?? 33 10 89 55 ?? 8b 45 ?? 8b 55 ?? 89 02 33 c0 89 45 a4 8b 45 ?? 83 c0 04 03 45 ?? 89 45 a8 6a 00 e8 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}