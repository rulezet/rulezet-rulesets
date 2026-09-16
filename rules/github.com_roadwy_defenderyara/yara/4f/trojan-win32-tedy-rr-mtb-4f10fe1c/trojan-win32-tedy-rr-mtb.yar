rule Trojan_Win32_Tedy_RR_MTB{
	meta:
		description = "Trojan:Win32/Tedy.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 d6 80 c6 9f 80 fe 1a 0f 92 c6 43 40 c0 e6 05 30 d6 88 31 41 4f } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}