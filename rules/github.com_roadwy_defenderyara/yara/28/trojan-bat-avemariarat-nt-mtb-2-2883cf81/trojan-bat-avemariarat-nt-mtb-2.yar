rule Trojan_BAT_AveMariaRAT_NT_MTB_2{
	meta:
		description = "Trojan:BAT/AveMariaRAT.NT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 ed 06 c7 06 c7 06 c7 06 c7 06 c7 06 ba 06 ec 06 fb 06 ed 06 ba 06 c7 06 fa 06 c7 06 f4 06 d4 06 cf 06 e8 06 ed } 		$a_01_1 = {c7 06 c7 06 cd 06 d0 06 ee 06 e9 06 da 06 c8 06 ff 06 fc 06 e7 06 c7 06 f4 06 d3 06 c9 06 c7 06 c7 06 c7 06 d1 06 c9 06 ee 06 f5 06 da 06 c9 06 d8 06 cb 06 d0 06 d8 06 d7 } 		$a_01_2 = {ca 06 cb 06 c7 06 d2 06 ed 06 c7 06 00 07 c7 06 c9 06 ba 06 c7 06 d3 06 c7 06 c7 06 fb 06 c7 06 ca 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 } 		$a_01_3 = {39 32 62 36 33 36 65 37 2d 37 66 38 30 2d 34 61 33 35 2d 62 66 35 39 2d 30 38 39 65 33 30 62 30 64 64 37 32 } 		$a_01_4 = {43 50 54 31 38 35 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}