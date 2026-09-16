rule Backdoor_Win32_Zegost_AD{
	meta:
		description = "Backdoor:Win32/Zegost.AD,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_00_0 = {2f 73 74 75 62 2e 64 61 74 } 		$a_03_1 = {8b d1 83 e2 01 80 fa 01 8a 14 01 75 05 80 f2 ?? eb 03 80 f2 ?? 88 14 01 41 3b ce } 	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*10) >=11
 
}