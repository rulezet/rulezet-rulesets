rule Trojan_Win32_LummaStealer_NIT_MTB_2{
	meta:
		description = "Trojan:Win32/LummaStealer.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {89 d9 80 c1 a8 32 0c 18 80 c1 b0 88 0c 18 43 83 fb 04 75 ec ff 25 ?? ?? ?? ?? 31 c9 39 10 0f 95 c1 31 c0 ff 24 8d ?? ?? ?? ?? 89 7d e8 8b 45 08 8b 48 3c 89 4d ec 8b 04 08 89 45 f0 89 f1 } 		$a_01_1 = {89 ca 80 c2 6d 32 14 08 80 c2 26 88 14 08 41 83 f9 14 75 ec } 		$a_01_2 = {0f b6 54 0e 94 89 d3 21 cb 00 db 28 da 0f b6 d2 01 ca 80 c2 28 88 54 0e 94 41 83 f9 70 75 e1 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}