rule Trojan_Win32_FileCoder_ARAX_MTB_2{
	meta:
		description = "Trojan:Win32/FileCoder.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 14 07 32 10 ff 85 c4 fd ff ff 88 14 01 33 d2 40 3b d6 72 eb } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}