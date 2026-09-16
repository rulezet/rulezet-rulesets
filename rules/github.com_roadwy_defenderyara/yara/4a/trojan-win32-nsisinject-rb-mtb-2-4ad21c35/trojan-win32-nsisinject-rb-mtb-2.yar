rule Trojan_Win32_NSISInject_RB_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {57 6a 40 68 00 30 00 00 68 00 09 3d 00 33 ff 57 ff d3 [0-20] 56 51 68 80 00 00 00 6a 03 51 6a 01 68 00 00 00 80 ff 75 10 ff 15 ?? ?? ?? ?? 8b f0 6a 00 56 ff 15 ?? ?? ?? ?? 6a 40 68 00 30 00 00 50 6a 00 89 45 fc ff d3 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}