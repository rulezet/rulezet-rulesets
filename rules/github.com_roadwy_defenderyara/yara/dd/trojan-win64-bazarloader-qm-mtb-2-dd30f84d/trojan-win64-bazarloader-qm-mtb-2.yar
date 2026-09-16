rule Trojan_Win64_BazarLoader_QM_MTB_2{
	meta:
		description = "Trojan:Win64/BazarLoader.QM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {48 89 44 24 70 48 8d 84 24 ac 00 00 00 48 89 44 24 78 48 8b 4c 24 78 48 8d 94 24 98 00 00 00 48 89 94 24 80 00 00 00 48 8b 8c 24 80 00 00 00 48 c7 02 ?? ?? ?? ?? 4c 8d 8c 24 b0 00 00 00 4c 89 8c 24 88 00 00 00 48 8b 8c 24 88 00 00 00 48 8b 4c 24 48 48 83 c1 18 48 89 8c 24 ?? ?? ?? ?? 48 8b 8c 24 ?? ?? ?? ?? 48 63 09 49 89 09 48 8b 4c 24 48 48 83 c1 10 48 89 4c 24 50 48 8b 4c 24 50 4c 8b 01 48 8b 4c 24 70 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}