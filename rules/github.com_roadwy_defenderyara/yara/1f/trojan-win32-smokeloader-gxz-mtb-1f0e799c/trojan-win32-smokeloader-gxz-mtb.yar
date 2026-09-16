rule Trojan_Win32_Smokeloader_GXZ_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {30 04 33 83 ff 0f 75 ?? ff 15 ?? ?? ?? ?? 46 3b f7 7c } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}