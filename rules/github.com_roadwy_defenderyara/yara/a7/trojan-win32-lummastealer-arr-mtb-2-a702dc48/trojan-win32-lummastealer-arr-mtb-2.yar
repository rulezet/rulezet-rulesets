rule Trojan_Win32_LummaStealer_ARR_MTB_2{
	meta:
		description = "Trojan:Win32/LummaStealer.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 06 00 00 "
		
	strings :
		$a_01_0 = {8d 71 ff 0f af f1 89 f1 f7 d1 21 ce 31 ce 89 f1 } 		$a_01_1 = {08 e5 88 ec 80 f5 01 20 c5 34 } 		$a_03_2 = {08 dd 30 dc 80 f5 ?? 08 e5 88 c4 30 d4 20 c2 20 c4 34 } 		$a_01_3 = {88 fc 08 c4 88 d0 88 de 80 f4 } 		$a_03_4 = {89 5d 98 0f af c1 89 c2 89 c6 25 ?? ?? ?? ?? f7 d2 81 e6 ?? ?? ?? ?? 89 d1 81 e1 } 		$a_01_5 = {88 d5 08 e1 20 c5 30 d0 88 cc 08 e8 88 c5 80 f4 } 	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*5+(#a_03_2  & 1)*20+(#a_01_3  & 1)*5+(#a_03_4  & 1)*20+(#a_01_5  & 1)*5) >=25
 
}