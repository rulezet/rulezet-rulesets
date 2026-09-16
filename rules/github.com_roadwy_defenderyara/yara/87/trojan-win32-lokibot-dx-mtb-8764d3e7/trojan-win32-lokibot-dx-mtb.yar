rule Trojan_Win32_LokiBot_DX_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.DX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {f6 d9 c0 c1 02 2a c8 80 f1 d1 c0 c1 02 f6 d9 c0 c1 03 2a c8 f6 d1 80 e9 21 80 f1 6e 2a c8 88 88 [0-04] 40 3d ?? ?? ?? ?? 72 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}