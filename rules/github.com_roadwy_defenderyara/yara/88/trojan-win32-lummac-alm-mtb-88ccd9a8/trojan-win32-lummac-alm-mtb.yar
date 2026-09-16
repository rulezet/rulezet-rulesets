rule Trojan_Win32_LummaC_ALM_MTB{
	meta:
		description = "Trojan:Win32/LummaC.ALM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c1 83 e1 02 81 f1 ce ?? ?? ?? 89 c2 83 e2 01 09 d1 80 c1 78 32 0c 04 80 f1 8e 80 c1 70 88 0c 04 83 f0 01 8d 04 50 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}