rule Trojan_Win64_Amadey_AMA_MTB{
	meta:
		description = "Trojan:Win64/Amadey.AMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 89 c8 99 41 f7 fb 48 63 d2 8a 44 14 08 42 32 04 09 43 88 04 0a 49 ff c1 45 39 c8 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}