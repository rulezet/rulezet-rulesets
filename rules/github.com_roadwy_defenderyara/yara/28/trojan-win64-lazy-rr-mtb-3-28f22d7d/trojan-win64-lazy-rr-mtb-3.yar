rule Trojan_Win64_Lazy_RR_MTB_3{
	meta:
		description = "Trojan:Win64/Lazy.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 f0 35 20 03 00 00 89 f9 81 f1 58 02 00 00 09 c1 0f 84 [0-05] 89 f0 35 00 04 00 00 89 f9 81 f1 00 03 00 00 09 c1 0f 84 [0-05] 81 f6 80 04 00 00 81 f7 60 03 00 00 09 f7 } 		$a_01_1 = {45 30 cb 45 0f b6 cb 49 01 f1 45 89 d3 41 c0 fb 07 45 30 d3 45 0f b6 d3 44 0f b6 5c 11 02 44 89 de 40 c0 fe 07 44 30 de 44 0f b6 de 4d 01 d3 4d 01 cb 44 0f b6 4c 11 03 45 89 ca 41 c0 fa 07 45 30 ca 41 0f b6 f2 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}