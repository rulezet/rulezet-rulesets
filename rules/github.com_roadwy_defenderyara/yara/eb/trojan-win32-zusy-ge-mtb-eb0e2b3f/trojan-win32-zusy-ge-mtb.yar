rule Trojan_Win32_Zusy_GE_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {24 26 02 c3 90 13 32 c3 90 13 02 c3 90 13 32 c3 90 13 2a c3 90 13 32 c3 90 13 2a c3 90 13 c0 c8 e4 90 13 aa 90 13 83 c1 ff } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}