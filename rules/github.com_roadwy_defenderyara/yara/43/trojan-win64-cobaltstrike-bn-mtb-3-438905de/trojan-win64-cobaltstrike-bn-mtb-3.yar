rule Trojan_Win64_CobaltStrike_BN_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.BN!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 44 1d 3b 8b 4d 37 02 cb 32 c8 88 4c 1d 3b 48 ff c3 48 83 fb 0b 72 e7 } 		$a_01_1 = {77 69 6e 64 6f 77 73 2e 69 6e 69 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}