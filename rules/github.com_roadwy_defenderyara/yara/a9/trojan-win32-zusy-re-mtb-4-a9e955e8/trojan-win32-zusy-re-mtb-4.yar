rule Trojan_Win32_Zusy_RE_MTB_4{
	meta:
		description = "Trojan:Win32/Zusy.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f4 8b 08 89 4d e8 8b 55 f4 8b 02 c1 e0 06 8b 4d f4 8b 11 c1 ea 08 33 c2 8b 4d f4 8b 09 03 c8 8b 45 fc 33 d2 f7 75 ec 8b 45 08 03 0c 90 03 4d fc 8b 55 f0 8b 02 2b c1 8b 4d f0 89 01 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}