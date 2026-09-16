rule Trojan_Win32_Stealerc_RP_MTB_4{
	meta:
		description = "Trojan:Win32/Stealerc.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {57 57 ff 15 7c a0 41 00 ff 15 14 a0 41 00 57 ff 15 a4 a0 41 00 81 fe ?? ?? ?? 00 7f 09 46 81 fe ?? ?? ?? 00 7c da } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}