rule Trojan_Win32_ArkeiStealer_RM_MTB_4{
	meta:
		description = "Trojan:Win32/ArkeiStealer.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 ff 3b d8 7e ?? 56 eb ?? 33 c0 81 fb 85 02 00 00 75 ?? 50 50 50 50 50 50 ff 15 ?? ?? ?? ?? 8b 44 24 ?? 8d 34 07 e8 ?? ?? ?? ?? 30 06 47 3b fb 7c } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}