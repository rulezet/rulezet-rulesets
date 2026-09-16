rule Trojan_Win32_VirLock_SK_MTB{
	meta:
		description = "Trojan:Win32/VirLock.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 06 90 32 c2 90 e9 00 00 00 00 } 		$a_01_1 = {88 07 42 46 90 47 49 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}