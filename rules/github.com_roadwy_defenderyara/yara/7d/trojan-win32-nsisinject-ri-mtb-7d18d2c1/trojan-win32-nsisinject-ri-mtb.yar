rule Trojan_Win32_NSISInject_RI_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b 5c 24 04 89 d8 c1 e8 1f 01 d8 2b 3c 24 d1 f8 89 f9 c1 e9 1f 01 f9 d1 f9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}