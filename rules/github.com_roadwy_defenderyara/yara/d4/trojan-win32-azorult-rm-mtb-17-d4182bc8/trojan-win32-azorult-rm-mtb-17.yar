rule Trojan_Win32_Azorult_RM_MTB_17{
	meta:
		description = "Trojan:Win32/Azorult.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c3 c1 ea 05 51 89 44 24 ?? c7 05 ?? ?? ?? ?? b4 21 e1 c5 c7 05 ?? ?? ?? ?? ff ff ff ff 03 d5 e8 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}