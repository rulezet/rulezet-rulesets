rule Backdoor_Win32_Simda_A{
	meta:
		description = "Backdoor:Win32/Simda.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {42 85 d2 7c 07 42 30 08 40 4a 75 fa c3 } 		$a_03_1 = {4b 85 db 75 ?? bb ?? ?? 00 00 b8 ?? ?? ?? ?? 8b cb ba ?? ?? 00 00 e8 ?? ?? ?? ?? 4b 85 db 75 ?? 6a 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}