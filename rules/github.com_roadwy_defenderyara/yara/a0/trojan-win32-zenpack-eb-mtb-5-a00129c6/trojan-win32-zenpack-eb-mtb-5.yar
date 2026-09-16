rule Trojan_Win32_Zenpack_EB_MTB_5{
	meta:
		description = "Trojan:Win32/Zenpack.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff ff 89 da 01 15 ?? ?? ?? ?? 89 f0 01 05 ?? ?? ?? ?? 55 8f 05 ?? ?? ?? ?? 89 f8 01 05 ?? ?? ?? ?? 83 f9 0a 74 d1 } 	condition:
		((#a_03_0  & 1)*6) >=6
 
}