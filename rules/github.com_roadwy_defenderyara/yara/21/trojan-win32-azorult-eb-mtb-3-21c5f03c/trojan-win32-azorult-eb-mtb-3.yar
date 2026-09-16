rule Trojan_Win32_Azorult_EB_MTB_3{
	meta:
		description = "Trojan:Win32/Azorult.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d ec 8b c7 d3 e0 8b 4d f4 8b d7 d3 ea 03 45 d4 89 45 fc 8b 45 e8 03 55 d0 03 c7 89 45 f0 8b 45 f0 31 45 fc 31 55 fc } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}