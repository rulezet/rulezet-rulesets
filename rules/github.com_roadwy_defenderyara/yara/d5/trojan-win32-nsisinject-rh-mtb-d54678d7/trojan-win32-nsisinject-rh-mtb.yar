rule Trojan_Win32_NSISInject_RH_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 30 00 00 68 00 09 3d 00 6a 00 ff 15 ?? ?? ?? ?? 89 45 f4 83 7d f4 00 75 07 [0-20] 6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 8b 4d 10 51 ff 15 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}