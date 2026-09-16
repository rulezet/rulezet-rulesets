rule Trojan_Win32_LummaC_GTM_MTB{
	meta:
		description = "Trojan:Win32/LummaC.GTM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {40 00 00 e0 2e 72 73 72 63 20 20 20 00 10 00 00 00 30 05 00 00 00 00 00 00 70 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 } 		$a_01_1 = {40 00 00 e0 2e 74 61 67 67 61 6e 74 00 30 00 00 00 60 2f } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}