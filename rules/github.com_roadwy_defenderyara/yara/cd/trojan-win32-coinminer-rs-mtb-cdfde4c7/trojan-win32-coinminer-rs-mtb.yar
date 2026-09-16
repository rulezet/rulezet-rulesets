rule Trojan_Win32_CoinMiner_RS_MTB{
	meta:
		description = "Trojan:Win32/CoinMiner.RS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {87 df 88 1c 08 87 df 41 39 d1 7d 21 0f b6 3c 19 85 ed 74 6b 89 c8 99 f7 fd 39 d5 76 59 0f b6 14 32 31 d7 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}