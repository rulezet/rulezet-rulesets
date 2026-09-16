rule Trojan_Win32_RedLine_CAS_MTB{
	meta:
		description = "Trojan:Win32/RedLine.CAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 dc 99 b9 41 00 00 00 f7 f9 8b 45 08 0f be 04 10 6b c0 ?? 99 b9 ?? 00 00 00 f7 f9 8b 55 0c 03 55 dc 0f b6 0a 33 c8 8b 55 0c 03 55 dc 88 0a eb } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}