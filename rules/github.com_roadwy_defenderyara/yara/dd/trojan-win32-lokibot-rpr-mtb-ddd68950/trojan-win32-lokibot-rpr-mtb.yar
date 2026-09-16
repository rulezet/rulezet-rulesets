rule Trojan_Win32_LokiBot_RPR_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.RPR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 4d ec 8b 45 ec 29 45 fc 89 7d f4 8b 45 e0 01 45 f4 2b 75 f4 ff 4d e8 8b 4d fc 89 75 ec } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}