rule Trojan_Win32_Delfinject_RM_MTB_2{
	meta:
		description = "Trojan:Win32/Delfinject.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {69 c0 77 01 00 00 8b 01 0f b7 18 f6 c7 f0 74 ?? a1 ?? ?? ?? ?? 8b 00 03 05 ?? ?? ?? ?? 66 81 e3 ff 0f 0f b7 db 03 c3 8b 1d ?? ?? ?? ?? 01 18 83 01 02 4a 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}