rule Trojan_Win32_Azorult_RTA_MTB_2{
	meta:
		description = "Trojan:Win32/Azorult.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 03 44 24 ?? 83 3d ?? ?? ?? ?? 1b 89 44 24 ?? c7 05 ?? ?? ?? ?? fc 03 cf ff 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}