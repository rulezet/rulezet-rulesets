rule Trojan_Win32_Virlock_VMX_MTB{
	meta:
		description = "Trojan:Win32/Virlock.VMX!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 06 90 32 c2 88 07 90 42 46 90 47 49 90 } 		$a_01_1 = {88 07 90 46 47 49 83 f9 00 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=5
 
}