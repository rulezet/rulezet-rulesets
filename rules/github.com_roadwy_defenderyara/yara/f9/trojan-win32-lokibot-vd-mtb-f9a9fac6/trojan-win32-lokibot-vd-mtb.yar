rule Trojan_Win32_Lokibot_VD_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc bf [0-40] 8a 01 34 ?? 8b d3 03 55 ?? 90 13 88 02 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}