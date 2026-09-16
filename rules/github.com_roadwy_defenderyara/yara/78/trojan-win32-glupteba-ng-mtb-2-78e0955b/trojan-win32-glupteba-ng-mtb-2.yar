rule Trojan_Win32_Glupteba_NG_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {75 24 e0 bf eb 0b 26 3e 75 1e 35 ?? ?? ?? ?? d8 cc f3 63 } 		$a_03_1 = {71 1e d1 4c 72 ?? 4d 73 5b e0 5a bb ?? ?? ?? ?? 72 3a 4d d7 } 	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}