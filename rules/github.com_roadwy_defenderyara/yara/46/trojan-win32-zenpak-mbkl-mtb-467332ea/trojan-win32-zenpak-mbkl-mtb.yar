rule Trojan_Win32_Zenpak_MBKL_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.MBKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 61 70 69 6d 6f 68 69 62 6f 7a 61 79 6f 63 65 78 6f 6a 69 6b 65 79 65 66 61 20 6b 61 63 75 6a 61 77 65 6d 6f 6a 69 6d 65 6e 61 64 61 6e 65 64 6f 6d 00 00 67 6f 63 75 79 65 6e 61 7a 65 74 6f 6a 61 62 6f 70 65 68 65 77 69 66 00 6c 65 77 61 79 69 76 65 73 75 72 65 6a 75 6d 65 77 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}