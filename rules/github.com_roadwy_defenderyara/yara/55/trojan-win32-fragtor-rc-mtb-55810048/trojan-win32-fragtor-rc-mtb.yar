rule Trojan_Win32_Fragtor_RC_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 34 24 8a 6d 00 8a 0e 31 f6 30 cd 88 6d 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}