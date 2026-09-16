rule Trojan_Win32_Amadey_AY_MTB{
	meta:
		description = "Trojan:Win32/Amadey.AY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c6 50 8b 84 31 ?? ?? ?? ?? 03 45 f4 50 ff 75 e4 ff 15 ?? ?? ?? ?? 8b 4d f8 83 c3 28 0f b7 47 06 41 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}