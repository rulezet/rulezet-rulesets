rule Trojan_Win32_LokiBot_RPT_MTB_3{
	meta:
		description = "Trojan:Win32/LokiBot.RPT!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 c8 80 f1 7b b2 5c 2a d1 32 d0 b1 12 2a ca c0 c9 02 2a c8 88 88 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}