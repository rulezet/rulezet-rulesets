rule Trojan_Win32_ClipBanker_RPX_MTB_4{
	meta:
		description = "Trojan:Win32/ClipBanker.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 4d f0 30 4c 05 f1 40 83 f8 0e 72 f3 } 		$a_01_1 = {8a 4d bc 30 4c 05 bd 40 83 f8 40 72 f3 } 		$a_01_2 = {8a 85 60 ff ff ff 30 84 0d 61 ff ff ff 41 83 f9 10 72 ed } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}