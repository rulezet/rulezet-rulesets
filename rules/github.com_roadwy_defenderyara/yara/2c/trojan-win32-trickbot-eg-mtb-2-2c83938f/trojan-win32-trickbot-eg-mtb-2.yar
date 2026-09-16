rule Trojan_Win32_Trickbot_EG_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.EG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6b c0 25 83 c0 56 99 6a 7f 59 f7 f9 88 55 ?? 33 c0 40 d1 e0 0f b6 80 ?? ?? ?? ?? 6b c0 25 83 c0 56 99 6a 7f 59 f7 f9 88 55 ?? 33 c0 40 6b c0 03 0f b6 80 ?? ?? ?? ?? 6b c0 25 83 c0 56 99 6a 7f 59 f7 f9 88 55 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}