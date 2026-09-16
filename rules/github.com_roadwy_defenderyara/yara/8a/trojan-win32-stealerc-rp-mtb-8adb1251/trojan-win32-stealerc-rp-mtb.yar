rule Trojan_Win32_Stealerc_RP_MTB{
	meta:
		description = "Trojan:Win32/Stealerc.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c0 3d cb d9 0b 00 75 06 81 c1 ?? ?? 00 00 40 3d 3d a6 15 00 7c eb } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}