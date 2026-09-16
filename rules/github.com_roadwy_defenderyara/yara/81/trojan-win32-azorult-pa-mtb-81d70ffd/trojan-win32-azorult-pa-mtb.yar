rule Trojan_Win32_Azorult_PA_MTB{
	meta:
		description = "Trojan:Win32/Azorult.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 cb 89 4c 24 10 8b 4c 24 18 03 c8 c1 e8 05 89 44 24 14 8b 44 24 2c 01 44 24 14 8b 44 24 10 33 c1 31 44 24 14 81 3d ?? ?? ?? ?? ba 05 00 00 89 44 24 10 c7 05 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}