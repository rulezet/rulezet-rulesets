rule Trojan_Win32_Ekstak_RE_MTB_7{
	meta:
		description = "Trojan:Win32/Ekstak.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 4c 24 0c 66 33 c0 80 e1 3f 5e 8a c1 83 c8 c0 83 c4 10 c3 90 90 90 90 90 90 90 90 90 90 90 90 90 90 55 8b ec e8 58 ff ff ff e9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}