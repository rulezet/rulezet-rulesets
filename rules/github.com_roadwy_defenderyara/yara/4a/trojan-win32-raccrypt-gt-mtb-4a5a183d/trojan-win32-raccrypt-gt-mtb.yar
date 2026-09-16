rule Trojan_Win32_Raccrypt_GT_MTB{
	meta:
		description = "Trojan:Win32/Raccrypt.GT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 44 24 ?? [0-04] 8b ?? 24 ?? 33 ?? 24 ?? 03 ?? 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 33 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}