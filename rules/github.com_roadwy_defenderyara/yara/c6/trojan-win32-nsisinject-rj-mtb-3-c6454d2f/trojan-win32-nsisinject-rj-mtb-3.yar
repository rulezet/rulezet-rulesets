rule Trojan_Win32_NSISInject_RJ_MTB_3{
	meta:
		description = "Trojan:Win32/NSISInject.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 00 09 3d 00 6a 54 8b 45 e4 50 e8 [0-10] 6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 b9 04 00 00 00 c1 e1 00 8b 55 0c 8b 04 0a 50 [0-20] 6a 40 68 00 30 00 00 8b 55 94 52 6a 00 ff 15 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}