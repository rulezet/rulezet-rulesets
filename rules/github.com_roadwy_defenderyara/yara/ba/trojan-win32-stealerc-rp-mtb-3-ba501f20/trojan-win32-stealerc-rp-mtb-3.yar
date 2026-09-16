rule Trojan_Win32_Stealerc_RP_MTB_3{
	meta:
		description = "Trojan:Win32/Stealerc.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 00 01 44 24 10 8b 54 24 10 8a 04 32 8b 0d ?? ?? ?? ?? 88 04 31 81 3d ?? ?? ?? ?? ?? ?? 00 00 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}