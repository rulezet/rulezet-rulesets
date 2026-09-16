rule Trojan_Win32_LokiBot_RPR_MTB_2{
	meta:
		description = "Trojan:Win32/LokiBot.RPR!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2a c8 32 c8 b2 61 2a d1 80 f2 b3 2a d0 32 d0 b1 01 2a ca } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}