rule Trojan_Win32_Zbot_BAH_MTB{
	meta:
		description = "Trojan:Win32/Zbot.BAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {50 5a c1 c2 0a c1 ca 02 c7 01 ?? ?? ?? ?? 31 01 83 c1 04 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}