rule Backdoor_Win32_Dridex{
	meta:
		description = "Backdoor:Win32/Dridex,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6b 65 72 00 75 00 33 32 2e 64 00 6e 65 6c 00 6c 6c 00 65 74 57 00 69 6e 64 6f 00 47 00 77 4c 6f } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}