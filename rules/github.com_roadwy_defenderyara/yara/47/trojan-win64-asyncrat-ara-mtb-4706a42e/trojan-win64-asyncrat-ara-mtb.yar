rule Trojan_Win64_AsyncRAT_ARA_MTB{
	meta:
		description = "Trojan:Win64/AsyncRAT.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 45 e8 48 89 c1 48 83 c0 01 48 89 45 e8 eb d9 48 8b 45 e8 48 8b 4d f0 48 01 c1 48 8b 45 e8 48 8b 55 10 48 01 c2 0f be 02 8b 55 18 31 d0 88 01 eb cd } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}