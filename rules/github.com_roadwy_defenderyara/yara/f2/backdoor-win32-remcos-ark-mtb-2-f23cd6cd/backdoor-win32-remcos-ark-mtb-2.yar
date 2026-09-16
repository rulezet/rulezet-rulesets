rule Backdoor_Win32_Remcos_ARK_MTB_2{
	meta:
		description = "Backdoor:Win32/Remcos.ARK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 f0 8b 45 ec e8 ?? ?? ?? ?? 8b d8 85 db 75 ?? 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 8b c6 8b 55 e8 e8 ?? ?? ?? ?? eb ?? ff 36 90 0a ef 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}