rule Trojan_Win32_Azorult_RW_MTB_17{
	meta:
		description = "Trojan:Win32/Azorult.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 fe c3 14 0c 18 89 [0-05] 7c [0-05] 8b 35 ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? 33 c9 89 4c 24 ?? 8d 64 24 ?? 81 f9 0d 04 00 00 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}