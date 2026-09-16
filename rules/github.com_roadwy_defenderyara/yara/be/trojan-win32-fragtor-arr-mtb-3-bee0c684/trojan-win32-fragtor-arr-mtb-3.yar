rule Trojan_Win32_Fragtor_ARR_MTB_3{
	meta:
		description = "Trojan:Win32/Fragtor.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f 57 c8 66 0f 6e c0 66 0f 7e 09 66 0f 70 c8 ?? 66 0f fe cb 66 0f 6e c2 0f 54 ca } 		$a_01_1 = {66 0f fe cd 66 0f 6e c7 0f 54 cc 66 0f 7e 1a 66 0f 67 c9 66 0f 67 c9 0f 57 c8 } 	condition:
		((#a_03_0  & 1)*6+(#a_01_1  & 1)*4) >=10
 
}