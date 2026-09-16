rule Trojan_Win32_LokiBot_RPO_MTB_2{
	meta:
		description = "Trojan:Win32/LokiBot.RPO!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 03 45 fc 88 10 8b 4d f8 03 4d fc 8a 11 80 ea 01 8b 45 f8 03 45 fc 88 10 e9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}