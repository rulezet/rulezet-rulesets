rule Trojan_Win32_IRCBot_RT_MTB{
	meta:
		description = "Trojan:Win32/IRCBot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 05 00 00 "
		
	strings :
		$a_03_0 = {81 c1 13 5d 5b 45 09 c9 e8 ?? ?? ?? ?? 29 db 43 b9 65 5b 3f 9c 31 10 21 cb 81 e9 c0 50 6b a8 41 81 c0 02 00 00 00 b9 65 1e 88 e2 39 f0 7c } 		$a_03_1 = {81 c2 04 4e df 72 e8 ?? ?? ?? ?? 29 d2 31 1f 81 e8 2d 95 16 35 09 d2 01 d0 81 c7 02 00 00 00 89 c2 81 e8 37 95 a6 ef 39 cf 7c } 		$a_03_2 = {81 eb 78 a9 ba c6 e8 ?? ?? ?? ?? 4a 31 07 81 ea 98 d7 0c f8 21 d3 09 d2 81 c7 02 00 00 00 89 da 39 cf 7c } 		$a_03_3 = {bf cc 46 47 00 48 e8 ?? ?? ?? ?? b8 83 5e ce f9 01 db 31 39 29 d8 21 c3 81 c1 02 00 00 00 09 c3 39 f1 7c } 		$a_03_4 = {81 c0 78 16 2b 7c e8 ?? ?? ?? ?? 81 c3 ?? ?? ?? ?? 31 17 89 d8 21 c0 29 db 81 c7 02 00 00 00 81 c0 37 be 54 81 68 d7 19 e4 24 58 39 cf 7c } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=1
 
}