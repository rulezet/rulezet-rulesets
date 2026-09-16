rule Trojan_Win32_Zusy_KK_MTB_3{
	meta:
		description = "Trojan:Win32/Zusy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c8 8d 47 01 33 ca 2b ca 80 f9 ?? 0f 45 c7 46 8b f8 3b f5 } 		$a_03_1 = {8b c8 33 ca 2b ca 8b 54 24 10 80 f9 ?? 8d 42 01 0f 45 c2 8b c8 8b 44 24 0c 40 89 4c 24 10 89 44 24 0c 3b c7 } 	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}