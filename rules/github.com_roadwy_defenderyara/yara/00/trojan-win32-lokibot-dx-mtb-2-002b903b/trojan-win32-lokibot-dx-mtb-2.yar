rule Trojan_Win32_LokiBot_DX_MTB_2{
	meta:
		description = "Trojan:Win32/LokiBot.DX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 e0 5e 00 00 [0-08] 66 81 f9 3f de 83 e9 04 [0-08] 8b 1c 0f [0-25] 31 f3 [0-30] 09 1c 08 [0-10] 7f [0-08] 89 c6 [0-10] c3 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}