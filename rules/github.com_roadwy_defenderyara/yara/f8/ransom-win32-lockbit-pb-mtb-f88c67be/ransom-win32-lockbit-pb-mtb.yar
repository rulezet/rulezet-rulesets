rule Ransom_Win32_LockBit_PB_MTB{
	meta:
		description = "Ransom:Win32/LockBit.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {52 00 65 00 73 00 74 00 6f 00 72 00 65 00 2d 00 4d 00 79 00 2d 00 46 00 69 00 6c 00 65 00 73 00 2e 00 74 00 78 00 74 00 } 		$a_01_1 = {2e 00 6c 00 6f 00 63 00 6b 00 62 00 69 00 74 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}