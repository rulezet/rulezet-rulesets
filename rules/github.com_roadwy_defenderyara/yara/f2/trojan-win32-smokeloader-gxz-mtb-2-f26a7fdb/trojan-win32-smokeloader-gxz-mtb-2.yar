rule Trojan_Win32_Smokeloader_GXZ_MTB_2{
	meta:
		description = "Trojan:Win32/Smokeloader.GXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {30 14 30 83 ff 0f ?? ?? 6a 00 6a 00 53 8d 44 24 ?? 50 55 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}