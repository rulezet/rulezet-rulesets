rule Trojan_Win32_NSISInject_RJ_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 04 68 00 30 00 00 68 00 5a 62 02 6a 00 ff 55 } 		$a_01_1 = {81 e1 03 09 01 00 81 e2 61 12 00 00 35 d3 6f 00 00 81 c2 c9 55 00 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}