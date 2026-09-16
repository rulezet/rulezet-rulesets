rule Trojan_Win32_Smokeloader_GMQ_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GMQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b ce c1 e9 ?? 03 cd 33 cf 31 4c 24 ?? c7 05 ?? ?? ?? ?? 19 36 6b ff c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 44 24 ?? 29 44 24 ?? 8d 44 24 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}