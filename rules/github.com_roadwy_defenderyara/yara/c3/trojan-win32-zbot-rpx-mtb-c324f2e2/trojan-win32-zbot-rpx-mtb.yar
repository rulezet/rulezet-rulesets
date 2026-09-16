rule Trojan_Win32_Zbot_RPX_MTB{
	meta:
		description = "Trojan:Win32/Zbot.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {64 8b 0d 30 00 00 00 f8 81 e8 00 00 00 00 f8 f5 8d 00 3c 8f c0 c8 28 60 60 60 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}