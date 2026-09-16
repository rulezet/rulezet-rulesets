rule Trojan_Win32_LummaC_EZ_MTB_3{
	meta:
		description = "Trojan:Win32/LummaC.EZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 20 20 00 20 20 20 20 00 80 06 00 00 10 00 00 00 de 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 88 03 00 00 00 90 06 00 00 04 00 00 00 ee 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}