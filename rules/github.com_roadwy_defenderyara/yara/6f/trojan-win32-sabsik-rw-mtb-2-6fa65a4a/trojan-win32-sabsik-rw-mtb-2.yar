rule Trojan_Win32_Sabsik_RW_MTB_2{
	meta:
		description = "Trojan:Win32/Sabsik.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 89 88 88 88 f7 e1 8b c6 c1 ea 03 8b ca c1 e1 04 2b ca 2b c1 0f b6 80 ?? ?? ?? ?? 30 86 ?? ?? ?? ?? 83 c6 02 81 fe 7e 07 00 00 72 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}