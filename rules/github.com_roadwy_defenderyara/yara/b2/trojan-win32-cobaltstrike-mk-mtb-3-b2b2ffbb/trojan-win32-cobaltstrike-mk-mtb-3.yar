rule Trojan_Win32_Cobaltstrike_MK_MTB_3{
	meta:
		description = "Trojan:Win32/Cobaltstrike.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 48 02 c1 e1 ?? 33 f9 0f b6 48 01 c1 e1 ?? 33 f9 0f b6 00 33 c7 69 f8 ?? ?? ?? ?? 8b c7 c1 e8 ?? 33 c7 69 c8 90 1b 02 5f 5e 8b c1 c1 e8 ?? 33 c1 c3 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}