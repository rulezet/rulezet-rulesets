rule Trojan_Win32_Zusy_R_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 04 06 c1 e0 06 be 04 00 00 00 c1 e6 00 8b 7d fc 8b 34 37 c1 ee 08 33 c6 8b 75 fc 8b 34 16 03 f0 8b 45 f8 33 d2 f7 75 f0 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}