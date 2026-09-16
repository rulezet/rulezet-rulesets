rule Trojan_Win32_DarkGate_GC_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 d2 f7 f3 8a 04 16 30 04 0f } 		$a_01_1 = {41 89 c8 81 f9 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}