rule Trojan_Win32_ArkeiStealer_RM_MTB_2{
	meta:
		description = "Trojan:Win32/ArkeiStealer.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 14 8d 3c 03 e8 ?? ?? ?? ?? 30 07 83 fd 19 75 [0-14] ff 15 ?? ?? ?? ?? ff 74 24 ?? 56 56 ff 15 ?? ?? ?? ?? 43 3b dd 7c } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}