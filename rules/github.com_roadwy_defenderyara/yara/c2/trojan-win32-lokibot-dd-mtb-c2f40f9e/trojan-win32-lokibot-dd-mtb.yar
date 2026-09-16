rule Trojan_Win32_LokiBot_DD_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b c7 8b de 8b d3 e8 ?? ?? ff ff 90 90 90 05 10 01 90 46 81 fe ?? ?? 00 00 75 } 		$a_02_1 = {8b c8 03 ca 8b c2 b2 ?? 32 90 90 ?? ?? ?? 00 88 11 c3 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}