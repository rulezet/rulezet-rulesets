rule Trojan_BAT_AsyncRAT_AP_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 18 91 08 00 0a 20 72 14 00 00 0b 03 04 6e 06 6a 58 05 6e 58 07 6a 58 69 61 10 01 03 2a } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}