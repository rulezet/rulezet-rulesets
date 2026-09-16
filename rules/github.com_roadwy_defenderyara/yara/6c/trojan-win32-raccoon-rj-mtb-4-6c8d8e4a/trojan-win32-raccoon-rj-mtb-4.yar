rule Trojan_Win32_Raccoon_RJ_MTB_4{
	meta:
		description = "Trojan:Win32/Raccoon.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 05 c7 05 ?? ?? ?? ?? 19 36 6b ff 89 45 ?? 8b 45 ?? 01 45 ?? 83 65 ?? 00 8b c6 c1 e0 ?? 03 45 ?? 33 45 ?? 33 c1 2b f8 8b 45 ?? 01 45 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}