rule Trojan_Win32_LokiBot_RPO_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.RPO!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 45 ff 0f b6 4d ff 83 e9 79 88 4d ff 8b 55 f8 8a 45 ff 88 82 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}