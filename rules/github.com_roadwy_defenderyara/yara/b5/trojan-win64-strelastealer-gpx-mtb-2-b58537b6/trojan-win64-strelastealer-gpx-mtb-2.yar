rule Trojan_Win64_StrelaStealer_GPX_MTB_2{
	meta:
		description = "Trojan:Win64/StrelaStealer.GPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 10 89 d1 f6 d1 89 c8 41 89 c8 88 8d 00 } 		$a_01_1 = {40 30 f1 08 d1 89 ca 80 f2 01 20 d1 89 d3 20 cb 30 d1 08 d9 } 		$a_01_2 = {45 6e 74 72 79 00 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=8
 
}