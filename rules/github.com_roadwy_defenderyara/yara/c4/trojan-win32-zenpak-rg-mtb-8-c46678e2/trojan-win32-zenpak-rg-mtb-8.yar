rule Trojan_Win32_Zenpak_RG_MTB_8{
	meta:
		description = "Trojan:Win32/Zenpak.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {88 3c 0e 88 1c 16 0f b6 0c 0e 01 f9 81 e1 ?? ?? ?? ?? 8a 1c 0e 8b 4d ?? 8b 7d ?? 32 1c 39 8b 4d ?? 88 1c 39 8b 4d ?? 01 cf 8b 4d ?? 39 cf 8b 4d ?? 89 4d ?? 89 55 ?? 89 7d ?? 74 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}