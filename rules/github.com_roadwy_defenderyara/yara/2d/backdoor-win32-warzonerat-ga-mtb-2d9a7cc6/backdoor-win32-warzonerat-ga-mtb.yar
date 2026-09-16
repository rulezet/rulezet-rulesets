rule Backdoor_Win32_WarzoneRAT_GA_MTB{
	meta:
		description = "Backdoor:Win32/WarzoneRAT.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_80_0 = {5c 57 37 48 36 34 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 52 69 6e 67 33 20 43 52 41 54 20 78 36 34 5c 52 69 6e 67 33 20 43 52 41 54 20 78 36 34 5c 6e 6f 70 65 2e 70 64 62 } 	condition:
		((#a_80_0  & 1)*10) >=10
 
}