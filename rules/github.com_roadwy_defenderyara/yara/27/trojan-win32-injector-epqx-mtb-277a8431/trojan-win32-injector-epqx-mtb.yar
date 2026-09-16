rule Trojan_Win32_Injector_EPQX_MTB{
	meta:
		description = "Trojan:Win32/Injector.EPQX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 83 c6 00 83 } 		$a_02_1 = {d2 d2 d2 d2 83 ea 00 81 34 2f ?? ?? ?? ?? 83 e8 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}