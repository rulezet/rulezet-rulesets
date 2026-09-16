rule Trojan_Win64_KeyLogger_NK_MTB{
	meta:
		description = "Trojan:Win64/KeyLogger.NK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {49 01 d0 4c 89 f2 4c 89 45 ?? 41 b8 02 00 00 00 e8 21 fc ff ff e9 e0 fe ff ff 48 8d 0d 3d e8 0a 00 48 c7 45 ?? 00 00 00 00 e8 98 fb ff ff } 		$a_03_1 = {48 8b 10 48 8d 4c 24 ?? 4c 8d 4c 24 ?? 41 b8 10 00 00 00 e8 2b 8f ff ff 85 c0 7e 17 0f b7 4c 24 ?? 66 89 4b 18 89 43 14 eb ab } 	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}