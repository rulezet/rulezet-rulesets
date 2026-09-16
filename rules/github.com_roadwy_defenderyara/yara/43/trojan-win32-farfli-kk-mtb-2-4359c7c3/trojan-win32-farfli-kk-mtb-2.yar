rule Trojan_Win32_Farfli_KK_MTB_2{
	meta:
		description = "Trojan:Win32/Farfli.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {99 b9 1a 00 00 00 f7 f9 46 3b f7 8a 54 14 10 88 54 1e ff } 		$a_01_1 = {65 6b 69 6d 68 75 71 63 72 6f 61 6e 66 6c 76 7a 67 64 6a 74 78 79 70 73 77 62 } 	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}