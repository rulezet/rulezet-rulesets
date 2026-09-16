rule Trojan_Win32_Qbot_PAL_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.PAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 04 8b 4d ?? 8a 14 02 32 14 19 8b 45 ?? 88 14 03 33 d2 8b 45 ?? c7 85 [0-08] 8b 48 ?? 8b 85 d4 00 00 00 05 12 b5 ff ff 03 c1 f7 75 0c } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}