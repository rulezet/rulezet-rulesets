rule Trojan_Win32_Lokibot_SG_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 fc 03 55 f8 90 05 0a 01 90 8a 03 90 05 0a 01 90 34 ?? 90 05 0a 01 90 88 02 90 05 0a 01 90 8d 45 f8 e8 ?? ?? ?? ?? 90 05 0a 01 90 43 4e 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}