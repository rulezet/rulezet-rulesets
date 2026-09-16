rule Trojan_Win64_Lazy_AHG_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AHG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_03_0 = {fb 80 33 00 60 01 00 00 00 80 32 00 58 f7 00 00 ?? ?? ?? 00 98 3d } 		$a_03_1 = {0b 02 0e 1d 00 fe 03 00 00 42 2f 00 00 00 ?? ?? ?? ?? ?? 00 00 10 } 		$a_01_2 = {20 20 20 20 20 20 20 20 f4 fd 03 00 00 10 00 00 00 f0 01 00 00 04 } 	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10+(#a_01_2  & 1)*5) >=35
 
}