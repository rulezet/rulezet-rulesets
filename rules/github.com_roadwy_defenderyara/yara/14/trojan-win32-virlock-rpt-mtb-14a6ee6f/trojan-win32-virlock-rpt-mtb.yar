rule Trojan_Win32_VirLock_RPT_MTB{
	meta:
		description = "Trojan:Win32/VirLock.RPT!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 06 32 c2 90 88 07 46 47 49 90 83 f9 00 90 e9 12 00 00 00 8b df 90 b9 80 03 00 00 ba d5 00 00 00 e9 da ff ff ff } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}