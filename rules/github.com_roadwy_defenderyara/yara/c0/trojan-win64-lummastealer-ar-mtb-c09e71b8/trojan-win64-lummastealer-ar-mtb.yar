rule Trojan_Win64_LummaStealer_AR_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {4c 8d 56 01 48 89 c1 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 45 31 db 41 89 d4 49 f7 eb 4c 39 d7 73 b4 48 89 94 24 60 04 00 00 } 		$a_03_1 = {48 8d 7c 24 18 48 8d 7f e0 66 0f 1f 84 00 00 00 00 00 0f 1f 44 00 00 48 89 6c 24 f0 48 8d 6c 24 f0 e8 ?? ?? ?? ?? 48 8b 6d 00 31 c9 } 	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}