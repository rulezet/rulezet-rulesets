rule Trojan_Win64_PoolInject_KK_MTB_2{
	meta:
		description = "Trojan:Win64/PoolInject.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 89 4b 10 48 89 4b 28 89 4b 30 48 89 4b 38 89 4b 40 48 89 4b 48 89 4b 50 48 89 4b 58 48 89 43 60 89 4b 18 } 		$a_03_1 = {33 d2 0f be 0d ?? ?? ?? 00 03 c5 03 c6 f7 f1 0f be 0d ?? ?? ?? 00 2b c1 0f af c7 85 c0 } 	condition:
		((#a_01_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}