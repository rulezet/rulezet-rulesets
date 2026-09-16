rule Trojan_Win32_Farfli_KK_MTB_3{
	meta:
		description = "Trojan:Win32/Farfli.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_03_0 = {89 46 14 89 5e 20 89 5e 18 89 5e 1c ?? ?? ?? ?? 89 46 24 89 5e 30 89 5e 28 89 5e 2c ?? ?? ?? ?? 89 46 34 89 5e 40 89 5e 38 89 5e 3c } 		$a_01_1 = {80 34 38 a7 40 3b c6 } 		$a_01_2 = {66 6e 74 31 31 32 32 74 64 6c 6c } 	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5) >=35
 
}