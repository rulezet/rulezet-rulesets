rule Trojan_Win32_Delfinject_RM_MTB{
	meta:
		description = "Trojan:Win32/Delfinject.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f6 c4 f9 74 ?? 8b 15 ?? ?? ?? ?? 8b 12 03 15 ?? ?? ?? ?? 66 25 ff 0f 0f b7 c0 03 d0 a1 ?? ?? ?? ?? 01 02 42 8d 14 1b 83 03 02 49 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}