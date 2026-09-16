rule Trojan_BAT_AsyncRAT_EAC_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.EAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 03 07 91 04 07 91 fe 01 16 fe 01 0c 08 39 02 00 00 00 16 0a 00 07 17 58 0b 07 03 8e 69 fe 04 0d 09 2d dc } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}