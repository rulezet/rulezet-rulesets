rule Trojan_Win32_KillMBR_ARAZ_MTB{
	meta:
		description = "Trojan:Win32/KillMBR.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {59 6f 75 72 20 64 69 73 6b 20 68 61 76 65 20 61 20 6c 6f 63 6b 21 50 6c 65 61 73 65 20 69 6e 70 75 74 20 74 68 65 20 75 6e 6c 6f 63 6b 20 70 61 73 73 77 6f 72 64 21 } 		$a_01_1 = {40 5c 5c 2e 5c 5c 70 68 79 73 69 63 61 6c 64 72 69 76 65 30 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}