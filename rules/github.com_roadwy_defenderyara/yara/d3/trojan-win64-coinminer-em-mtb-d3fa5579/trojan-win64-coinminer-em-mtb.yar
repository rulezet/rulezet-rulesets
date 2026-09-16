rule Trojan_Win64_CoinMiner_EM_MTB{
	meta:
		description = "Trojan:Win64/CoinMiner.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {4d 8d 40 01 41 8b c1 41 ff c1 f7 f7 0f b6 04 32 41 30 40 ff } 	condition:
		((#a_01_0  & 1)*7) >=7
 
}