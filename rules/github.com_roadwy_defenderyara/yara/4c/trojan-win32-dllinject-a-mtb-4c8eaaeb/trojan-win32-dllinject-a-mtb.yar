rule Trojan_Win32_DllInject_A_MTB{
	meta:
		description = "Trojan:Win32/DllInject.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_03_0 = {15 10 ff 15 00 ?? 11 10 6a 00 6a 00 6a 01 68 ?? ?? 15 10 ff 15 04 ?? 11 10 c7 05 ?? ?? 15 10 0c 00 00 00 c7 05 } 	condition:
		((#a_03_0  & 1)*7) >=7
 
}