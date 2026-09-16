rule Trojan_Win32_LummaC_GNT_MTB{
	meta:
		description = "Trojan:Win32/LummaC.GNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 40 00 00 c0 2e 69 64 61 ?? 61 20 20 00 10 00 00 00 } 		$a_01_1 = {40 00 00 e0 2e 72 73 72 63 00 00 00 fc 02 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}