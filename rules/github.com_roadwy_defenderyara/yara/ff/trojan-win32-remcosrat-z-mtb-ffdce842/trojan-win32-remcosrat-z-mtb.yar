rule Trojan_Win32_RemcosRAT_Z_MTB{
	meta:
		description = "Trojan:Win32/RemcosRAT.Z!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {52 65 6d 63 6f 73 } 		$a_81_1 = {25 30 32 69 3a 25 30 32 69 3a 25 30 32 69 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}