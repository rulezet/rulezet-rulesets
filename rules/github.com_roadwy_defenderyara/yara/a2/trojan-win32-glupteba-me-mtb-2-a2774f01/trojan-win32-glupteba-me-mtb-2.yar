rule Trojan_Win32_Glupteba_ME_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.ME!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8d 14 31 8d 41 40 30 02 41 83 f9 20 72 f2 } 		$a_01_1 = {8d 14 31 8d 41 40 30 02 41 83 f9 05 72 f2 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}