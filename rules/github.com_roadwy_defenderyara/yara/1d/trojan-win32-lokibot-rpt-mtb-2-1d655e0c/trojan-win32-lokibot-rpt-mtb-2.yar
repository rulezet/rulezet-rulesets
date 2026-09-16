rule Trojan_Win32_LokiBot_RPT_MTB_2{
	meta:
		description = "Trojan:Win32/LokiBot.RPT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 04 0e 2c [0-10] 02 c1 [0-10] f6 d8 [0-10] f6 d0 [0-10] 32 c1 [0-10] 02 c1 [0-10] f6 d8 [0-10] 32 c1 f6 d8 88 04 0e } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}