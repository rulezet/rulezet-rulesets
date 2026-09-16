rule Trojan_Win32_Stealerc_AMBH_MTB{
	meta:
		description = "Trojan:Win32/Stealerc.AMBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 ec 31 45 fc 33 55 fc 89 55 ec 8b 45 ec 83 45 f4 64 29 45 f4 83 6d f4 64 83 3d ?? ?? ?? ?? 0c } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}