rule Trojan_Win32_NSISInject_DK_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {fe c8 fe c0 fe c8 fe c8 fe c8 2c 77 fe c0 2c 7e 2c 51 2c 83 fe c8 fe c0 04 f6 fe c0 34 76 2c 48 fe c8 04 d3 2c cf 88 81 ?? ?? ?? ?? 83 c1 01 eb } 		$a_03_1 = {34 1c 34 ad fe c0 fe c8 04 48 fe c0 fe c0 34 6f 34 e2 2c b4 34 72 04 0c fe c0 2c dc fe c8 fe c0 2c 06 fe c0 04 93 88 81 ?? ?? ?? ?? 83 c1 01 eb } 		$a_03_2 = {04 2d 34 2a 2c 94 fe c8 2c 0f fe c0 fe c8 04 5a fe c0 fe c0 34 6b 2c 05 fe c0 2c b5 34 35 04 e4 34 f6 34 a9 fe c8 88 81 ?? ?? ?? ?? 83 c1 01 eb } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}