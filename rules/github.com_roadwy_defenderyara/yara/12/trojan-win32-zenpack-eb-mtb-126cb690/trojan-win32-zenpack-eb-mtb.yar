rule Trojan_Win32_Zenpack_EB_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 d8 8b 7d e4 0f b6 14 17 31 d1 88 cb 8b 4d d4 8b 55 e8 88 1c 0a } 	condition:
		((#a_01_0  & 1)*7) >=7
 
}