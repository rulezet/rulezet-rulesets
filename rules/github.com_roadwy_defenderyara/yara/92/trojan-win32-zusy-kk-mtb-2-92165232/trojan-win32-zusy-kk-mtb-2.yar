rule Trojan_Win32_Zusy_KK_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a c3 f6 eb 32 45 13 8a cb c0 e1 02 32 ca 02 c1 00 44 1d f8 43 83 fb 08 } 		$a_01_1 = {8b 55 fc 30 0c 02 40 3b 45 0c } 		$a_01_2 = {70 63 6c 44 72 61 67 6f 76 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5) >=35
 
}