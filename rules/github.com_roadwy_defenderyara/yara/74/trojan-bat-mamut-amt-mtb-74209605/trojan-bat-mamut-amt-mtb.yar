rule Trojan_BAT_Mamut_AMT_MTB{
	meta:
		description = "Trojan:BAT/Mamut.AMT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 04 17 73 ?? 00 00 0a 0c 28 ?? 06 00 06 0d 08 09 16 09 8e 69 6f ?? 00 00 0a 07 6f ?? 00 00 0a 13 05 de 18 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}