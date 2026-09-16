rule Trojan_Win64_Lazy_ARR_MTB_4{
	meta:
		description = "Trojan:Win64/Lazy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_03_0 = {41 89 ee 41 80 f6 ?? 45 0f b6 f6 46 8d 34 75 01 00 00 00 41 bc ?? ?? ?? ?? 45 31 ed e9 4a } 		$a_01_1 = {4d 89 ec 49 d1 ec 48 89 c2 4c 29 e2 4d 01 ec 4c 39 e1 4c 0f 47 e1 49 39 d5 4c 89 e2 48 0f 47 d0 48 ff c2 } 		$a_03_2 = {45 0f b6 f6 46 8d 34 75 ?? ?? ?? ?? 41 bc 03 00 00 00 45 31 ed e9 4a } 	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*20+(#a_03_2  & 1)*10) >=60
 
}