rule Backdoor_MacOS_GetShell_A{
	meta:
		description = "Backdoor:MacOS/GetShell.A,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 61 00 00 02 6a 02 5f 6a 01 5e 48 31 d2 0f 05 49 89 c4 48 89 c7 b8 62 00 00 02 48 31 f6 56 48 be ?? ?? ?? ?? ?? ?? ?? ?? 56 48 89 e6 6a 10 5a 0f 05 4c 89 e7 b8 5a 00 00 02 48 31 f6 0f 05 b8 5a 00 00 02 48 ff c6 0f 05 48 31 c0 b8 3b 00 00 02 e8 08 00 00 00 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}