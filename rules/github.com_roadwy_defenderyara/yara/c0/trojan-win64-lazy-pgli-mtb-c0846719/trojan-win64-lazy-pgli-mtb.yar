rule Trojan_Win64_Lazy_PGLI_MTB{
	meta:
		description = "Trojan:Win64/Lazy.PGLI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {38 30 39 39 37 35 66 38 2d 64 35 34 62 2d 34 61 64 62 2d 61 38 30 61 2d 63 32 64 32 31 31 34 36 33 35 35 63 00 00 00 00 31 39 33 2e 31 34 33 2e 31 2e 32 33 38 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}