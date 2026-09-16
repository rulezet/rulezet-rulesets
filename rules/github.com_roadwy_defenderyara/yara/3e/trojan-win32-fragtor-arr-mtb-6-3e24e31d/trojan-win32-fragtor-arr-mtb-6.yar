rule Trojan_Win32_Fragtor_ARR_MTB_6{
	meta:
		description = "Trojan:Win32/Fragtor.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a cb f6 d1 32 cb 80 e1 ?? 32 d9 8d 55 } 		$a_01_1 = {4a 00 4a 00 56 00 31 00 33 00 4a 00 33 00 54 00 71 00 51 00 4e 00 6a 00 39 00 34 00 50 00 76 00 30 00 36 00 39 00 4b 00 77 00 61 00 6c 00 46 00 33 00 69 00 5a 00 76 00 44 00 39 00 38 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*20) >=30
 
}