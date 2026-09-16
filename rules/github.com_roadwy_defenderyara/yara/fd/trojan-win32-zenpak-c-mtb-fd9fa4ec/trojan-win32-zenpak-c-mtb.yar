rule Trojan_Win32_Zenpak_C_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e8 8b 4d f0 8a 14 01 8b 75 ec 88 14 06 05 01 00 00 00 8b 7d f4 39 f8 89 45 e8 75 e2 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}