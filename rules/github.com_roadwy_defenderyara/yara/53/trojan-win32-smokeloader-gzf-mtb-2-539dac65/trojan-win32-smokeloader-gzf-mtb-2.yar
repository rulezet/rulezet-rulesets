rule Trojan_Win32_Smokeloader_GZF_MTB_2{
	meta:
		description = "Trojan:Win32/Smokeloader.GZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 0c 24 b9 00 00 00 00 81 c1 ?? ?? ?? ?? 01 f1 81 e9 ?? ?? ?? ?? 31 01 59 51 } 		$a_03_1 = {c1 e1 03 49 81 f1 ?? ?? ?? ?? 31 cb 31 e1 83 ea 01 52 ff 0c 24 5a c1 ea 05 c1 ea 08 } 	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}