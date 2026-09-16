rule Trojan_Win32_LokiBot_SR_MTB_3{
	meta:
		description = "Trojan:Win32/LokiBot.SR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 02 3c 61 72 [0-04] 3c 7a 77 [0-04] 2c 20 88 06 42 46 4b } 		$a_03_1 = {b0 b7 8b 15 [0-04] 89 15 [0-04] 8b 15 [0-04] 8a 92 [0-04] 88 15 [0-04] 8b d6 03 d3 89 15 [0-04] 30 05 [0-04] 90 05 10 01 90 a0 [0-04] 8b 15 [0-04] 88 02 a1 [0-04] a3 [0-04] a1 [0-04] 83 c0 02 a3 [0-04] 90 05 10 01 90 43 81 fb [0-04] 75 a1 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}