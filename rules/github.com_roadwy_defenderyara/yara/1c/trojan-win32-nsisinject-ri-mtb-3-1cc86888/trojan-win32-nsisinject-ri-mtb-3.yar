rule Trojan_Win32_NSISInject_RI_MTB_3{
	meta:
		description = "Trojan:Win32/NSISInject.RI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 00 5a 62 02 e8 ?? ?? ?? ?? 83 c4 04 89 45 f0 68 00 5a 62 02 68 ff 00 00 00 8b 45 f0 50 e8 ?? ?? ?? ?? 83 c4 0c 83 7d f0 00 75 07 33 c0 e9 ?? ?? ?? ?? 8d 8d c0 fd ff ff 51 68 03 01 00 00 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}