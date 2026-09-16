rule Trojan_Win32_Sabsik_RM_MTB{
	meta:
		description = "Trojan:Win32/Sabsik.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 39 8e e3 38 f7 e1 8b c6 c1 ea 02 8d 0c d2 03 c9 2b c1 0f b6 80 ?? ?? ?? ?? 30 86 ?? ?? ?? ?? 83 c6 02 81 fe 7e 07 00 00 72 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}