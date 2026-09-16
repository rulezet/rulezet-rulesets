rule Trojan_Win32_Miuref_A{
	meta:
		description = "Trojan:Win32/Miuref.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 25 73 25 69 2e 25 69 2e 25 69 2e 25 69 2f 00 } 		$a_03_1 = {c6 06 7b ff 37 8d 46 01 6a ?? 6a ?? 50 e8 ?? ?? ?? ?? c6 46 09 2d 0f b7 47 04 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}