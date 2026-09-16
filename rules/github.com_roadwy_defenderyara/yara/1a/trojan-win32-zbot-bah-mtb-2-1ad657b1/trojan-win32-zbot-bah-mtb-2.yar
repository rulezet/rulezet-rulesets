rule Trojan_Win32_Zbot_BAH_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.BAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 ee 02 8d 76 01 29 de 31 db 4b 21 f3 c7 42 ?? ?? ?? ?? ?? 31 32 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}