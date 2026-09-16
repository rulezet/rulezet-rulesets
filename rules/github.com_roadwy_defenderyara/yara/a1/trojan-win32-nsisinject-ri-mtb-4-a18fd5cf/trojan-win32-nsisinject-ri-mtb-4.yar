rule Trojan_Win32_NSISInject_RI_MTB_4{
	meta:
		description = "Trojan:Win32/NSISInject.RI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 00 09 3d 00 6a 08 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 89 45 ?? 83 7d ?? 00 75 05 e9 ?? ?? ?? ?? 68 00 09 3d 00 [0-70] 89 45 ?? 6a 40 68 00 30 00 00 8b [0-03] 6a 00 ff 15 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}