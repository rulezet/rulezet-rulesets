rule Trojan_Win64_CoinMiner_KK_MTB{
	meta:
		description = "Trojan:Win64/CoinMiner.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {32 ca 41 32 c8 41 32 ca 41 88 4f ff 6b c8 ?? 41 8a c3 c0 e8 ?? 45 02 db 0f b6 c0 41 32 c9 41 32 0f 41 32 ca 41 88 0f 6b c8 ?? 41 32 cb 41 32 4f 01 41 32 ca 41 88 4f 01 4d 03 fc 48 83 ed } 		$a_01_1 = {37 30 63 64 31 63 32 39 2d 65 66 32 64 2d 34 64 30 31 2d 62 65 34 30 2d 30 38 31 31 63 35 35 34 62 66 34 31 } 	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}