rule Trojan_Win32_RedLine_RPX_MTB_7{
	meta:
		description = "Trojan:Win32/RedLine.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 dc 83 c0 01 89 45 dc 8b 4d dc 3b 4d 10 73 30 8b 45 dc 99 b9 41 00 00 00 f7 f9 8b 45 08 0f be 0c 10 69 c9 19 14 00 00 83 e1 45 8b 55 0c 03 55 dc 0f b6 02 33 c1 8b 4d 0c 03 4d dc 88 01 eb bf } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}