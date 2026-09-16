rule Trojan_Win64_LummaStealer_PST_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.PST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {1b 34 c2 fe eb 37 30 58 ab 64 ec 1d a1 fa 0b e2 01 74 85 25 35 f7 26 3e e5 02 d5 66 56 2a aa 97 8e 12 fb 81 ed 85 1f 9a e2 94 1b a8 a9 94 8b 69 47 65 00 7e 7b 1e 41 4f da db 8a 0d d6 01 84 75 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}