rule Trojan_Win64_LummaStealer_PST_MTB_2{
	meta:
		description = "Trojan:Win64/LummaStealer.PST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {de 1b 12 93 c1 44 e2 b9 6f 5f 63 3e 8c 41 cf ba d9 e5 4f ef 34 a4 ea 87 30 d4 81 42 60 62 fa 60 e7 c5 d1 01 b0 00 16 b5 cb 18 ?? ?? ?? ?? 5b b5 2e ca 48 a5 7d 19 db be 59 52 75 7c 62 3d 6b 5f f0 78 8f 20 3d b5 24 4e 28 4c 40 26 e7 7d 25 04 e8 3c 53 64 4d b1 13 0f 76 e9 3d 05 f0 02 ba 1e 2a f1 fe 3a } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}