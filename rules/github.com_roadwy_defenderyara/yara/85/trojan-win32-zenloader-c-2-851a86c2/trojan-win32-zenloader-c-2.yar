rule Trojan_Win32_Zenloader_C_2{
	meta:
		description = "Trojan:Win32/Zenloader.C,SIGNATURE_TYPE_PEHSTR,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_01_0 = {70 6c 61 74 66 6f 72 6d 63 6c 69 65 6e 74 6d 61 69 6e } 		$a_01_1 = {72 75 6e 6d 6f 64 75 6c 65 } 		$a_01_2 = {23 35 30 30 38 23 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10) >=30
 
}