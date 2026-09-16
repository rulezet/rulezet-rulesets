rule Trojan_Win32_RopProof_RPX_MTB{
	meta:
		description = "Trojan:Win32/RopProof.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {69 6f 73 65 72 31 32 } 		$a_01_1 = {4a 61 76 61 5f 63 6f 6d 5f 73 75 6e 5f 63 6f 72 62 61 5f 73 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}