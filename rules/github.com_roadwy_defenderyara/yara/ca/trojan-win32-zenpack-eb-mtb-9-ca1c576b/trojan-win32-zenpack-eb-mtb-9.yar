rule Trojan_Win32_Zenpack_EB_MTB_9{
	meta:
		description = "Trojan:Win32/Zenpack.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_03_0 = {40 83 ea 05 01 d0 83 f0 01 01 25 ?? ?? ?? ?? 31 d0 29 c2 29 d0 b9 02 00 00 00 e2 2d 4a 83 f2 07 ba 04 00 00 00 8d 05 ?? ?? ?? ?? 31 28 8d 05 } 	condition:
		((#a_03_0  & 1)*7) >=7
 
}