rule Backdoor_Win32_Lotok_GMF_MTB{
	meta:
		description = "Backdoor:Win32/Lotok.GMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {b0 6c 51 52 c6 44 24 ?? 43 c6 44 24 ?? 74 c6 44 24 ?? 54 c6 44 24 ?? 68 88 5c 24 24 c6 44 24 ?? 4b c6 44 24 ?? 52 c6 44 24 ?? 4e c6 44 24 ?? 4c c6 44 24 ?? 33 c6 44 24 ?? 32 c6 44 24 ?? 2e 88 44 24 ?? 88 44 24 ?? 88 5c 24 ?? ff 15 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}