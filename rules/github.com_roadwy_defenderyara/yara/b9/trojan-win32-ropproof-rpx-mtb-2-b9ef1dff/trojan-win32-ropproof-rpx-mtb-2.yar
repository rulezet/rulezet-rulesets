rule Trojan_Win32_RopProof_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/RopProof.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {98 5b f1 e9 4b 1d 61 4e 4b da fc a7 6b f9 23 4f 3e 6a 59 fd 73 70 05 df 76 61 24 18 e6 ab 09 7d 0d } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}