rule Trojan_Win32_ArkeiStealer_RMA_MTB{
	meta:
		description = "Trojan:Win32/ArkeiStealer.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c4 89 84 24 ?? ?? ?? ?? 55 8b ac 24 ?? ?? ?? ?? 56 57 33 f6 33 ff 3b de 7e ?? 81 fb 85 02 00 00 75 [0-08] ff 15 [0-10] e8 ?? ?? ?? ?? 30 04 2f 83 fb 19 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}