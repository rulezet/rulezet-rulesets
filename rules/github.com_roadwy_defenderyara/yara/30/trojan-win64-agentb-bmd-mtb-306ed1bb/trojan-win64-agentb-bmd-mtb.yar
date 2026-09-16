rule Trojan_Win64_Agentb_BMD_MTB{
	meta:
		description = "Trojan:Win64/Agentb.BMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 89 c8 99 41 f7 fb 48 63 d2 8a 44 14 ?? 42 32 04 09 43 88 04 0a 49 ff c1 45 39 c8 7f } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}