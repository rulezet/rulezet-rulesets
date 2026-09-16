rule TrojanDropper_Win32_Sirefef_gen_D{
	meta:
		description = "TrojanDropper:Win32/Sirefef.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {e4 26 16 91 cc 1d 46 59 39 03 00 00 3c 77 cd 6b } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}