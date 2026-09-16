rule Trojan_Win32_Zenpack_EN_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_03_0 = {b9 03 00 00 00 55 8f 05 ?? ?? ?? ?? 89 f8 01 05 ?? ?? ?? ?? e2 d0 31 c0 40 c3 89 45 00 d0 d0 d0 d0 d0 d0 d0 d0 } 	condition:
		((#a_03_0  & 1)*7) >=7
 
}