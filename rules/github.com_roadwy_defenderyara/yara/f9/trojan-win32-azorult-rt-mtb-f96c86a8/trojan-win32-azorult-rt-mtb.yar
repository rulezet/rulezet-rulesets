rule Trojan_Win32_Azorult_RT_MTB{
	meta:
		description = "Trojan:Win32/Azorult.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {3d 9c 06 00 00 74 ?? 40 89 45 ?? 3d 81 84 13 01 0f } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}