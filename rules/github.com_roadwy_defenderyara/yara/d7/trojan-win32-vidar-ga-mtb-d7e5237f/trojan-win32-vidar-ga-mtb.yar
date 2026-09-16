rule Trojan_Win32_Vidar_GA_MTB{
	meta:
		description = "Trojan:Win32/Vidar.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c8 8b 45 f8 33 d2 f7 f1 8b 45 0c 8a 0c 02 8b 45 f0 8b 55 08 32 0c 02 88 08 } 	condition:
		((#a_01_0  & 1)*4) >=4
 
}