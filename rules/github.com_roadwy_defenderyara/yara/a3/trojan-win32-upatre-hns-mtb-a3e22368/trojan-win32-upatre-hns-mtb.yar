rule Trojan_Win32_Upatre_HNS_MTB{
	meta:
		description = "Trojan:Win32/Upatre.HNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {c5 00 2c 86 08 d0 14 4a 4a c3 f2 ee 45 15 64 23 3d e0 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}