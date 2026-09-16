rule Trojan_Win64_Lazy_AMCW_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AMCW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 20 20 00 c0 40 00 00 10 00 00 00 4e 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 a0 ae 00 00 00 d0 40 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}