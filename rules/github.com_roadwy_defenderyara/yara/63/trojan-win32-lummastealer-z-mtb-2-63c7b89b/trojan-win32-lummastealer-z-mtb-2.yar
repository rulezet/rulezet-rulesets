rule Trojan_Win32_LummaStealer_Z_MTB_2{
	meta:
		description = "Trojan:Win32/LummaStealer.Z!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {34 24 8b 54 24 10 8b 0c 82 89 5c 24 0c 8b 04 9a 8b 04 87 89 7c 24 04 8b 0c 8f 0f b7 74 05 1c 0f b7 5c 0d 1c 89 f2 89 74 24 14 39 de 72 02 89 da 89 5c 24 28 8d 34 28 8d 1c 28 83 c3 2e 8d 04 32 83 c0 2e 89 44 24 08 85 d2 74 4e 01 e9 83 c1 2e ?? ?? ?? ?? ?? 0f b6 13 89 d0 04 bf 3c 1a 73 03 80 c2 20 89 d6 0f b6 01 89 c2 80 c2 bf 80 fa 1a 73 02 04 20 8b 7c 24 04 89 f2 38 c2 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}