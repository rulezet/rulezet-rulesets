rule Trojan_Win64_Lazy_AV_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 21 cb 48 09 fb 48 21 c8 4c 21 ca 48 09 c2 48 31 da 48 09 f1 48 f7 d1 48 09 d1 48 b8 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}