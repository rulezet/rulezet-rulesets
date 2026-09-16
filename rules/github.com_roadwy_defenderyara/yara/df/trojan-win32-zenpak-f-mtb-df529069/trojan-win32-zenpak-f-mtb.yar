rule Trojan_Win32_Zenpak_F_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 3c 06 01 d7 89 45 d4 31 d2 8b 5d f0 f7 f3 8b 75 ec 0f b6 14 16 01 d7 89 f8 99 f7 f9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}