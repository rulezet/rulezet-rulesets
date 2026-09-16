rule Trojan_Win32_SmokeLoader_BKK_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.BKK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 eb 03 8d 49 00 8d b5 ?? ?? ff ff c7 85 ?? ?? ff ff 00 00 00 00 e8 ?? ?? ff ff 8a 95 ?? ?? ff ff 8b 85 ?? ?? ff ff 30 14 38 83 fb 0f 75 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}