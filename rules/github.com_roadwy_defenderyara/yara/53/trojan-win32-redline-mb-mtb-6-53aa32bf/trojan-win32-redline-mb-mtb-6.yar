rule Trojan_Win32_Redline_MB_MTB_6{
	meta:
		description = "Trojan:Win32/Redline.MB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d 0c 73 28 8b 45 fc 33 d2 b9 04 00 00 00 f7 f1 8b 45 10 0f b6 0c 10 8b 55 08 03 55 fc 0f b6 02 33 c1 8b 4d 08 03 4d fc 88 01 eb c7 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}