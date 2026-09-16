rule Trojan_Win32_Stealerc_RP_MTB_2{
	meta:
		description = "Trojan:Win32/Stealerc.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 8c 38 4b 13 01 00 a1 ?? ?? ?? ?? 88 0c 38 8b 0d ?? ?? ?? ?? 81 f9 ?? 04 00 00 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}