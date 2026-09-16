rule Trojan_BAT_AsyncRAT_AR_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 1d 20 31 01 00 00 9d 06 1c 20 f5 26 00 00 9d 06 19 20 b8 38 00 00 9d 06 17 20 6b 19 00 00 9d 06 16 20 b9 03 00 00 9d } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}