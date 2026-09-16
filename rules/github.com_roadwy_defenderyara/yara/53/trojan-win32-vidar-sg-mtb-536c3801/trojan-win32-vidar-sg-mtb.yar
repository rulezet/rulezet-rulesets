rule Trojan_Win32_Vidar_SG_MTB{
	meta:
		description = "Trojan:Win32/Vidar.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 f7 f1 8b 45 fc 68 ?? ?? ?? ?? 8a 0c 02 8b 55 08 03 d6 8a 04 13 32 c1 88 02 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}