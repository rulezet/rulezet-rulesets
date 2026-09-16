rule Trojan_Win32_ArkeiStealer_RMA_MTB_2{
	meta:
		description = "Trojan:Win32/ArkeiStealer.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 f6 85 ff 7e ?? 55 8b 2d ?? ?? ?? ?? 8b ff 83 ff 2d 75 ?? 6a 00 6a 00 6a 00 6a 00 6a 00 ff d5 6a 00 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 04 1e 81 ff 91 05 00 00 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}