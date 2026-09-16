rule Trojan_Win32_Smokeloader_GZZ_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d 08 30 04 ?? 83 ff 0f 75 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}