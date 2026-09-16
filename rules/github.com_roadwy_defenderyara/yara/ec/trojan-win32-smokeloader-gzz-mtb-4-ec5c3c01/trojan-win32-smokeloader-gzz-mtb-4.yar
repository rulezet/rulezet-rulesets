rule Trojan_Win32_Smokeloader_GZZ_MTB_4{
	meta:
		description = "Trojan:Win32/Smokeloader.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 ff d5 6a 00 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 04 33 46 3b f7 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}