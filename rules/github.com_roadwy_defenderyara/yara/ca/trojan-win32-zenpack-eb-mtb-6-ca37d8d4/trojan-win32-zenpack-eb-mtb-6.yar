rule Trojan_Win32_Zenpack_EB_MTB_6{
	meta:
		description = "Trojan:Win32/Zenpack.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 18 ba 01 00 00 00 4a 8d 05 ?? ?? ?? ?? 31 38 01 c2 4a 8d 05 ?? ?? ?? ?? 01 28 01 c2 4a 8d 05 ?? ?? ?? ?? 89 30 eb cc } 	condition:
		((#a_03_0  & 1)*6) >=6
 
}