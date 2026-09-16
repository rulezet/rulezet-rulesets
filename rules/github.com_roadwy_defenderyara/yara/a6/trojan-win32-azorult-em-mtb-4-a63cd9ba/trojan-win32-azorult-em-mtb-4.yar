rule Trojan_Win32_Azorult_EM_MTB_4{
	meta:
		description = "Trojan:Win32/Azorult.EM!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 75 f4 8b 4d f0 8b c6 d3 e0 8b 4d fc 8b d6 c1 ea 05 03 45 d0 03 55 d4 03 ce 33 c1 33 c2 2b f8 89 55 f8 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}