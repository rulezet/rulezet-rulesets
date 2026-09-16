rule Trojan_Win32_Raccrypt_GP_MTB_2{
	meta:
		description = "Trojan:Win32/Raccrypt.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 44 24 ?? 8b 44 24 ?? 8b 4c 24 ?? 33 44 24 ?? 03 4c 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 90 17 02 01 01 31 33 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}