rule Trojan_Win32_Amadey_GPA_MTB{
	meta:
		description = "Trojan:Win32/Amadey.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 04 30 32 06 88 45 ff 8d 45 ff 50 c6 45 c0 } 	condition:
		((#a_01_0  & 1)*4) >=4
 
}