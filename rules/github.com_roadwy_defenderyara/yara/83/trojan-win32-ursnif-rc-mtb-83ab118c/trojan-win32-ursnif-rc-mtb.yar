rule Trojan_Win32_Ursnif_RC_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 40 8b 4c 24 2c 01 44 24 24 0f af c8 8b 44 24 24 2b c1 a3 } 		$a_01_1 = {48 3a 5c 66 6c 6f 77 5c 72 65 70 72 6f 64 75 63 74 69 76 69 74 79 5c 61 63 74 5c 73 63 72 69 70 74 73 2e 70 64 62 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}