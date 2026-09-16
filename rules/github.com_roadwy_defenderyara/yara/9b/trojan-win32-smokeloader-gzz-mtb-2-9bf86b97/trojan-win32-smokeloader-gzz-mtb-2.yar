rule Trojan_Win32_Smokeloader_GZZ_MTB_2{
	meta:
		description = "Trojan:Win32/Smokeloader.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 85 ff ?? ?? e8 ?? ?? ?? ?? 30 04 32 42 3b d7 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}