rule Trojan_Win32_Trickbot_EF_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.EF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6b c0 2f 83 c0 47 99 6a 7f 59 f7 f9 88 55 ?? 33 c0 40 6b c0 03 0f b6 80 ?? ?? ?? ?? 6b c0 2f 83 c0 47 99 6a 7f 59 f7 f9 88 55 ?? 33 c0 40 c1 e0 02 0f b6 80 ?? ?? ?? ?? 6b c0 2f 83 c0 47 99 6a 7f 59 f7 f9 88 55 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}