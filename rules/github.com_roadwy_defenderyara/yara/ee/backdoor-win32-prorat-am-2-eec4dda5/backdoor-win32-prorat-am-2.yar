rule Backdoor_Win32_Prorat_AM_2{
	meta:
		description = "Backdoor:Win32/Prorat.AM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {54 72 6f 6a 61 6e 20 48 6f 72 73 65 20 2d 20 43 6f 64 65 64 20 62 79 } 		$a_01_1 = {2e 64 6c 6c 00 48 6f 6f 6b 50 72 6f 63 00 49 6e 73 74 61 6c 6c 48 6f 6f 6b 00 52 65 6d 6f 76 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}