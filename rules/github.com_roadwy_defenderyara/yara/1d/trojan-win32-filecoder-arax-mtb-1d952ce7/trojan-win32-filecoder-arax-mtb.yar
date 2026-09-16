rule Trojan_Win32_FileCoder_ARAX_MTB{
	meta:
		description = "Trojan:Win32/FileCoder.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 55 e0 03 d0 40 8a 0c 13 32 0a 88 0c 16 3b c7 72 ee } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}