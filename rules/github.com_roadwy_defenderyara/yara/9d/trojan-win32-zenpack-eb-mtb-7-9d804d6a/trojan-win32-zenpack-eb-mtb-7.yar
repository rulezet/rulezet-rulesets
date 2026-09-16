rule Trojan_Win32_Zenpack_EB_MTB_7{
	meta:
		description = "Trojan:Win32/Zenpack.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff ff 89 da 01 15 ?? ?? ?? ?? 89 f0 01 05 ?? ?? ?? ?? b9 03 00 00 00 55 8f 05 ?? ?? ?? ?? 89 f8 01 05 ?? ?? ?? ?? e2 d5 31 c0 40 c3 } 	condition:
		((#a_03_0  & 1)*6) >=6
 
}