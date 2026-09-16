rule Trojan_Win32_Raccrypt_GV_MTB_5{
	meta:
		description = "Trojan:Win32/Raccrypt.GV!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 00 e1 34 ef c6 c3 } 		$a_01_1 = {01 08 c3 29 08 c3 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}