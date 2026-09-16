rule Trojan_Win32_ICLoader_AIC_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.AIC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b f8 a1 34 30 4c 00 c7 44 24 10 00 00 00 00 8d 14 09 8b 1d 20 11 4c 00 0b d0 68 9c 30 4c 00 89 54 24 10 57 df 6c 24 14 dc 05 58 30 4c 00 dd 1d 58 30 4c 00 ff d3 89 06 68 88 30 4c 00 57 ff d3 89 46 04 68 74 30 4c 00 57 ff d3 89 46 08 68 64 30 4c 00 57 ff d3 8b 0e } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}