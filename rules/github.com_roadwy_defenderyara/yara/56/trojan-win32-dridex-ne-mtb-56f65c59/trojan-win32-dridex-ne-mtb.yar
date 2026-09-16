rule Trojan_Win32_Dridex_NE_MTB{
	meta:
		description = "Trojan:Win32/Dridex.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 02 00 00 "
		
	strings :
		$a_00_0 = {8a 4d f7 88 ca 80 e2 e4 88 55 f7 8b 75 08 88 4d f7 83 fe 00 89 45 e8 } 		$a_81_1 = {46 46 50 47 47 4c 42 4d 2e 70 64 62 } 	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*3) >=13
 
}