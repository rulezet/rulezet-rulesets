rule Trojan_Win32_Ekstak_RE_MTB_3{
	meta:
		description = "Trojan:Win32/Ekstak.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 4d b0 e8 f0 93 07 00 68 9c 20 6b 00 8d 4d b0 e8 43 94 07 00 b9 41 00 00 00 33 c0 bf a4 29 72 00 f3 ab } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}