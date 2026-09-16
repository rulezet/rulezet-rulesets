rule Trojan_Win64_DonutLoader_TL_MTB{
	meta:
		description = "Trojan:Win64/DonutLoader.TL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 b9 04 00 00 00 41 b8 00 30 00 00 31 c9 ba 00 00 50 00 ff d0 49 89 c5 48 85 c0 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}