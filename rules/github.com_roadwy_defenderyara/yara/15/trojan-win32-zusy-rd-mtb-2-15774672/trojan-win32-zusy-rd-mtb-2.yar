rule Trojan_Win32_Zusy_RD_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {76 74 72 62 79 74 6e 75 79 6b 69 2e 64 6c 6c 00 74 72 62 64 79 74 6a 75 6e 00 64 74 72 62 79 74 6e 75 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}