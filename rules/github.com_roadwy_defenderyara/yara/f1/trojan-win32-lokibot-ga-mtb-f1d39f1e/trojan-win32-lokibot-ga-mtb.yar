rule Trojan_Win32_LokiBot_GA_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 f8 8a 80 [0-20] 34 e9 8b 55 ?? 03 55 ?? 88 02 [0-20] 8b 45 ?? 8a 80 [0-20] 8b 55 ?? 03 55 ?? 88 02 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}