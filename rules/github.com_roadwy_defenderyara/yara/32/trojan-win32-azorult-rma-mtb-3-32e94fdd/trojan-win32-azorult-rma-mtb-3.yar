rule Trojan_Win32_Azorult_RMA_MTB_3{
	meta:
		description = "Trojan:Win32/Azorult.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 fe 93 8d 6a 8d 04 16 31 85 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 31 45 ?? 81 3d ?? ?? ?? ?? a3 01 00 00 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}