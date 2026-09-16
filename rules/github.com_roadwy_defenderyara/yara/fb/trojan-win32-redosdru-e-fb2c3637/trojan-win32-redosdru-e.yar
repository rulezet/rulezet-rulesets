rule Trojan_Win32_Redosdru_E{
	meta:
		description = "Trojan:Win32/Redosdru.E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 7c 56 e8 ?? ?? ?? 00 83 c4 08 85 c0 74 da } 		$a_01_1 = {8b cd 2b cf 8b ee 8a 14 01 80 f2 62 88 10 40 83 ed 01 75 f2 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}