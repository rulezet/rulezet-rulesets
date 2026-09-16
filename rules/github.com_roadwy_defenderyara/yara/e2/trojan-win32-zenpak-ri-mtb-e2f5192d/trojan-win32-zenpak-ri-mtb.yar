rule Trojan_Win32_Zenpak_RI_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.RI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 45 0c 8a 4d 08 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 30 c8 a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 6c 0c 00 00 88 45 ff 8a 45 ff 0f b6 c0 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}