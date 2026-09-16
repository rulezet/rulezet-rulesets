rule Trojan_Win32_FileCoder_ARAQ_MTB{
	meta:
		description = "Trojan:Win32/FileCoder.ARAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 79 73 74 65 6d 20 69 73 20 65 6e 63 72 79 70 74 65 64 20 42 79 20 52 41 4e 53 4f 4d 43 52 59 50 54 4f } 		$a_01_1 = {3a 2f 2f 52 61 6e 73 6f 6d 43 72 79 70 74 6f 5f 71 6f 69 61 36 45 31 46 6b 6f 51 6a 65 66 41 39 69 61 31 30 2e 6f 6e 69 6f 6e } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}