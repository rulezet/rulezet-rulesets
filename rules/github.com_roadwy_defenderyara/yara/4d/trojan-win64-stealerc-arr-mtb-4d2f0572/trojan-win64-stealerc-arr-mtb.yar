rule Trojan_Win64_StealerC_ARR_MTB{
	meta:
		description = "Trojan:Win64/StealerC.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 f7 ee 48 d1 ?? 48 8d 0c 52 48 8d 0c 4a 48 29 ce 0f 57 db f2 48 0f 2a de } 		$a_03_1 = {48 89 d7 49 f7 ec 48 d1 ?? 4d 89 e7 49 c1 fc ?? 4c 29 e2 4c 8d 24 } 	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}