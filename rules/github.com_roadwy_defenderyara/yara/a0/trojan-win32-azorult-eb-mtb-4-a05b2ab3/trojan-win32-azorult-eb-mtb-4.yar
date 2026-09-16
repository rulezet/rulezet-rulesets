rule Trojan_Win32_Azorult_EB_MTB_4{
	meta:
		description = "Trojan:Win32/Azorult.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d e4 8b d6 d3 e2 89 5d e8 03 55 c8 89 55 f4 8b 45 f0 01 45 e8 8b 45 dc 90 01 45 e8 8b 45 e8 89 45 e0 8b 4d ec 8b c6 d3 e8 89 45 f8 } 	condition:
		((#a_01_0  & 1)*8) >=8
 
}