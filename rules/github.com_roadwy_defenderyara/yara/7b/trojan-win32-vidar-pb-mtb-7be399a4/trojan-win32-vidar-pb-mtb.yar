rule Trojan_Win32_Vidar_PB_MTB{
	meta:
		description = "Trojan:Win32/Vidar.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 88 8d 0c 06 33 d2 8b c6 f7 75 84 8a 04 3a 8b 55 80 32 04 0a 46 88 01 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}