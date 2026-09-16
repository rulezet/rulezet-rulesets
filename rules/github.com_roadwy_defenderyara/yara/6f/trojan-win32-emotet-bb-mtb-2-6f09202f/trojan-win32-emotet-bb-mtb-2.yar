rule Trojan_Win32_Emotet_BB_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 02 00 00 "
		
	strings :
		$a_00_0 = {8b 6c 24 1c 8b 5c 24 20 03 c6 57 8b 7c 24 28 8d 04 40 c7 44 24 14 00 00 00 00 2b c7 03 c5 8d 5c 18 05 8d 41 01 } 		$a_01_1 = {6c 23 23 42 2b 6b 26 72 42 24 63 62 5e 41 48 61 35 34 25 2a 6f 44 71 65 45 75 73 6b 46 6e 38 56 68 40 56 34 6c } 	condition:
		((#a_00_0  & 1)*10+(#a_01_1  & 1)*3) >=13
 
}