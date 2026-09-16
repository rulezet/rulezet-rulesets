rule Trojan_Win64_DisguisedXMRigMiner_MX_MTB{
	meta:
		description = "Trojan:Win64/DisguisedXMRigMiner.MX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {85 c0 74 1f 0f bf 44 24 40 0f bf 4c 24 50 89 05 0e bf 21 00 0f bf 44 24 4c 2b c8 ff c1 89 0d f3 be 21 00 48 8b 4c 24 58 48 33 cc } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}