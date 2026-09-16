rule Trojan_Win32_Ursnif_BW_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.BW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {43 6c 6f 73 65 5c 45 69 67 68 74 5c 61 67 65 5c 6b 69 6e 67 5c 4f 72 67 61 6e 5c 73 65 61 5c 6d 75 73 69 63 5c 4b 69 6e 67 68 69 6c 6c 2e 70 64 62 } 		$a_01_1 = {50 00 6c 00 61 00 6e 00 64 00 65 00 65 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}