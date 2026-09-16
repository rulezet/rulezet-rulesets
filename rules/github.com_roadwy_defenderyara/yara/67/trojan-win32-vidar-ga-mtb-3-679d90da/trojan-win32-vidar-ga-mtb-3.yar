rule Trojan_Win32_Vidar_GA_MTB_3{
	meta:
		description = "Trojan:Win32/Vidar.GA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d2 8b c3 f7 75 08 8b 45 0c 8d 0c 33 8a 04 02 8b 55 fc 32 04 0a 43 88 01 3b df 72 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}