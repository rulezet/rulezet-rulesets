rule Trojan_BAT_QQPass_NIT_MTB{
	meta:
		description = "Trojan:BAT/QQPass.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 18 02 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 13 1d 2b 45 11 1d 6f ?? 00 00 0a 74 1a 00 00 01 13 1e 00 72 64 05 00 70 13 1f 11 1e 6f ?? 00 00 0a 1b 6f ?? 00 00 0a 6f ?? 00 00 0a 13 20 02 73 2c 00 00 0a 28 ?? 00 00 06 00 02 28 ?? 00 00 06 11 20 6f ?? 00 00 0a 00 00 11 1d 6f ?? 00 00 0a 2d b2 de 16 } 		$a_01_1 = {54 55 4b 53 79 73 74 65 6d 46 6f 72 53 65 6c 6c } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}