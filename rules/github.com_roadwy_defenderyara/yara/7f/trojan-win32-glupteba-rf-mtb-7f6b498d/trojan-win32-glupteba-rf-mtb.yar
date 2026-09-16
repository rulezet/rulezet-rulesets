rule Trojan_Win32_Glupteba_RF_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {be 86 72 18 5f 46 89 ff e8 ?? ?? ?? ?? 01 f7 47 31 02 81 ee 01 00 00 00 81 c2 01 00 00 00 81 ef 9a f8 1a ff 4e 39 da 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}