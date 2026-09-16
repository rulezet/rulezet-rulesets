rule Backdoor_Win64_Bazarldr_MBK_MTB_2{
	meta:
		description = "Backdoor:Win64/Bazarldr.MBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f be f3 01 fe 89 f3 c1 e3 [0-01] 01 f3 89 df c1 ff [0-01] 31 df 0f b6 5d 00 48 83 c5 01 84 db 75 } 		$a_03_1 = {0f be f3 01 ee 89 f3 c1 e3 [0-01] 01 f3 89 dd c1 fd [0-01] 31 dd 0f b6 19 48 83 c1 01 84 db 75 } 		$a_03_2 = {8d 6c ed 00 89 e9 c1 f9 [0-01] 31 e9 89 ce c1 e6 [0-01] 01 ce 81 fe [0-04] 74 [0-01] 48 83 c7 01 4c 39 ff 72 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}