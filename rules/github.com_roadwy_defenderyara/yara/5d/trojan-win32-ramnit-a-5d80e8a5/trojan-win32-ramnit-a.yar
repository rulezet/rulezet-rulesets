rule Trojan_Win32_Ramnit_A{
	meta:
		description = "Trojan:Win32/Ramnit.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4a 8a 1c 32 32 1f 88 1f 47 4a e2 ed } 		$a_01_1 = {6a 05 8f 45 f0 6a 04 8d 85 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}