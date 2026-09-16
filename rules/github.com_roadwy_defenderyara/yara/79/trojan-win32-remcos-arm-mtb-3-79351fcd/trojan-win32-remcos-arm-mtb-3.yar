rule Trojan_Win32_Remcos_ARM_MTB_3{
	meta:
		description = "Trojan:Win32/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d8 03 5d a4 6a 00 e8 ?? ?? ?? ?? 2b d8 8b 45 d4 31 18 83 45 ec 04 6a 00 e8 ?? ?? ?? ?? 83 c0 04 01 45 d4 8b 45 ec 3b 45 d0 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}