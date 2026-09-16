rule Trojan_Win32_Trickbot_MX_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {99 b9 42 1a 00 00 f7 f9 0f b6 94 15 ?? ?? ?? ?? 30 53 ff 83 7d 0c 00 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}