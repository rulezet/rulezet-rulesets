rule Trojan_Win32_Fareit_SS_MTB_5{
	meta:
		description = "Trojan:Win32/Fareit.SS!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 7d fc 00 76 34 8b 45 fc bf 05 00 00 00 33 d2 f7 f7 85 d2 75 14 8a 01 34 7c 8b d3 03 55 fc 73 05 e8 36 72 f7 ff 88 02 eb 10 8b c3 03 45 fc 73 05 e8 26 72 f7 ff 8a 11 88 10 ff 45 fc 41 81 7d fc 67 92 00 00 75 b9 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}