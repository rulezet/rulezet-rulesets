rule Trojan_Win32_RedLine_BQ_MTB_2{
	meta:
		description = "Trojan:Win32/RedLine.BQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 45 b4 8b 45 bc 33 d2 f7 75 b4 8b 4d 10 0f b6 14 11 0f b6 45 c3 33 c2 88 45 eb 8b 4d 08 03 4d bc 8a 55 eb 88 11 eb } 	condition:
		((#a_01_0  & 1)*4) >=4
 
}