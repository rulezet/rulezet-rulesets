rule Trojan_Win32_LokiBot_RPT_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.RPT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 45 ff 0f b6 4d ff 2b 4d f8 88 4d ff 0f b6 55 ff 81 f2 ?? ?? ?? ?? 88 55 ff 0f b6 45 ff f7 d8 88 45 ff 0f b6 4d ff } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}