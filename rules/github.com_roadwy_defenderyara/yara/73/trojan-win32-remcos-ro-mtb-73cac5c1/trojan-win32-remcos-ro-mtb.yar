rule Trojan_Win32_Remcos_RO_MTB{
	meta:
		description = "Trojan:Win32/Remcos.RO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 04 0a 34 ?? 04 ?? 34 ?? 2c ?? 88 01 41 83 ee 01 75 ?? 68 de c0 ad de } 		$a_02_1 = {8a 04 0a 34 ?? 2c ?? 34 ?? 2c ?? 88 01 41 83 ee 01 75 ?? 68 de c0 ad de } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}