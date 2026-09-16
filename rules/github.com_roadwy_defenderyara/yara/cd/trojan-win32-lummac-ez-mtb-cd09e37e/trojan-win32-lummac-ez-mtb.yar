rule Trojan_Win32_LummaC_EZ_MTB{
	meta:
		description = "Trojan:Win32/LummaC.EZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 45 eb 24 01 0f b6 c0 8b 4d f4 31 e9 89 45 bc } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}