rule Trojan_Win32_NSISInject_RI_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.RI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {57 6a 40 68 00 30 00 00 68 00 09 3d 00 33 c9 89 45 f0 33 ff 89 45 f4 57 89 4d fc 89 45 ec ff d3 [0-25] 56 51 68 80 00 00 00 6a 03 51 6a 01 68 00 00 00 80 ff 75 10 ff 15 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}