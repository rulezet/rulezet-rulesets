rule Trojan_Win32_Cobaltstrike_MK_MTB{
	meta:
		description = "Trojan:Win32/Cobaltstrike.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {a1 fc fe 54 00 33 c1 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 01 05 90 1b 00 8b ff a1 ?? ?? ?? ?? 8b 0d 90 1b 00 89 08 5f 5d c3 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}