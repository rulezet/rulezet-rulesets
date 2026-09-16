rule Trojan_Win32_Azorult_RWA_MTB{
	meta:
		description = "Trojan:Win32/Azorult.RWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 ec 98 09 00 00 83 3d ?? ?? ?? ?? 37 0f [0-05] 33 c0 89 45 ?? 89 45 ?? 89 45 ?? 89 45 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}