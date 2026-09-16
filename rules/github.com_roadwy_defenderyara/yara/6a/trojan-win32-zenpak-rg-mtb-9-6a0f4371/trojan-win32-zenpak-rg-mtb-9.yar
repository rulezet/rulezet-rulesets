rule Trojan_Win32_Zenpak_RG_MTB_9{
	meta:
		description = "Trojan:Win32/Zenpak.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {fe ff ff 45 75 1e 80 bd ?? fe ff ff 4c 75 15 31 c0 80 bd ?? fe ff ff 2e 89 85 ?? fe ff ff 0f 84 ?? ff ff ff } 		$a_01_1 = {41 72 66 72 75 69 74 66 75 6c 73 61 77 2e 6c 69 6b 65 6e 65 73 73 63 69 73 6e 2e 74 2e 6b 64 6f 6e 2e 74 67 72 65 61 74 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}