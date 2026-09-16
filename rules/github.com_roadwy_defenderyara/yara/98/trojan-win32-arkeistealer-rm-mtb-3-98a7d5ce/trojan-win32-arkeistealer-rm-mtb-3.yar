rule Trojan_Win32_ArkeiStealer_RM_MTB_3{
	meta:
		description = "Trojan:Win32/ArkeiStealer.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b f2 33 ed 8b d9 57 8b fd 85 f6 7e ?? 81 fe 85 02 00 00 75 ?? 55 55 55 55 55 55 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 04 1f 47 3b fe 7c } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}