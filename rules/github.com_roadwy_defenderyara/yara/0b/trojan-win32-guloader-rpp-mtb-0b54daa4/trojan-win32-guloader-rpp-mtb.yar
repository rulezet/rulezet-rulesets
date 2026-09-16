rule Trojan_Win32_Guloader_RPP_MTB{
	meta:
		description = "Trojan:Win32/Guloader.RPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {09 1c 38 ff 45 38 ff 4d 38 fc 83 c7 04 ff 45 38 ff 4d 38 83 04 24 00 81 ff ?? ?? ?? ?? 75 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}