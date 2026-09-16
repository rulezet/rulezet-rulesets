rule Trojan_Win32_Emotet_KMG_MTB_12{
	meta:
		description = "Trojan:Win32/Emotet.KMG!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {40 3d 27 16 00 00 7c } 		$a_01_1 = {8a d0 0a c1 f6 d2 0a d3 22 d0 8b 44 24 10 88 16 46 48 89 44 24 10 75 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}