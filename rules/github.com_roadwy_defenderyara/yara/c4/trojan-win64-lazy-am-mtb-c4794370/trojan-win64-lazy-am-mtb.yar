rule Trojan_Win64_Lazy_AM_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 89 c9 41 f7 d1 89 ce 83 f6 fe 89 f7 21 cf 89 ca 83 ca 01 89 f8 f7 d0 89 d3 81 e3 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}