rule Trojan_Win64_GenCBL_ARA_MTB_2{
	meta:
		description = "Trojan:Win64/GenCBL.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 42 04 30 44 15 e0 48 ff ?? 48 83 fa ?? 72 f0 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}