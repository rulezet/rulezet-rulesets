rule Trojan_Win32_Gcleaner_AGL_MTB{
	meta:
		description = "Trojan:Win32/Gcleaner.AGL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {50 6a 02 ff 75 ac ff d6 6a 04 8d 45 c8 c7 45 c8 ?? ?? ?? ?? 50 6a 41 ff 75 ac ff d6 83 7d c4 10 8d 45 b0 6a 01 0f 43 45 b0 53 6a 03 ff 77 40 ff 77 3c 6a 50 50 ff 75 ac } 		$a_01_1 = {31 38 35 2e 31 35 36 2e 37 33 2e 39 38 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*4) >=5
 
}