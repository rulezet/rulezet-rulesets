rule Trojan_BAT_FileCoder_ARA_MTB_2{
	meta:
		description = "Trojan:BAT/FileCoder.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {3a 5c 55 73 65 72 73 5c 57 6f 72 6d 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 42 53 4f 44 5c 42 53 4f 44 5c 6f 62 6a 5c 44 65 62 75 67 5c 42 53 4f 44 2e 70 64 62 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}