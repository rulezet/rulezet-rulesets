rule Trojan_Win32_Smokeloader_GZZ_MTB_5{
	meta:
		description = "Trojan:Win32/Smokeloader.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 69 c6 05 ?? ?? ?? ?? 2e c7 05 ?? ?? ?? ?? 6d 67 33 32 c7 05 ?? ?? ?? ?? 64 6c 6c 00 a2 ?? ?? ?? ?? ff 15 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}