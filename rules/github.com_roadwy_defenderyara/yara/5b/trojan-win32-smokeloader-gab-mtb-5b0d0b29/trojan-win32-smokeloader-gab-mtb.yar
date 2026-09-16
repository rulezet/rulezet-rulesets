rule Trojan_Win32_Smokeloader_GAB_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 69 72 74 c7 05 ?? ?? ?? ?? 6f 74 65 63 c7 05 ?? ?? ?? ?? 75 61 6c 50 c6 05 ?? ?? ?? ?? 72 66 c7 05 ?? ?? ?? ?? 74 00 ff 15 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}