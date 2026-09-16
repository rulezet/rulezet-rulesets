rule Trojan_Win32_Virlock_ARAX_MTB{
	meta:
		description = "Trojan:Win32/Virlock.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {32 c2 88 07 42 90 46 47 90 49 e9 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}