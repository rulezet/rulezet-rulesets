rule Trojan_Win32_Emotet_BY_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.BY!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 10 6a 22 33 d2 5f 8d 0c 06 8b c6 f7 f7 8b 44 24 0c 8a 04 50 30 01 46 3b 74 24 14 75 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}