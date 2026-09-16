rule Trojan_Win32_Emotet_DEM_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DEM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 dc 2b c8 8b 55 e0 2b ca 8b 45 e4 2b c8 2b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 8b 55 0c 8b 45 e8 88 04 0a } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}