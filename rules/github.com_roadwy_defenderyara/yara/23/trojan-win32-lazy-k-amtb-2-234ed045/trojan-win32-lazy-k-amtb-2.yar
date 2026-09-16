rule Trojan_Win32_Lazy_K_AMTB_2{
	meta:
		description = "Trojan:Win32/Lazy.K!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {f3 41 0f 6f 00 66 0f 6f ca 0f 57 c8 f3 41 0f 7f 08 f3 41 0f 6f 40 10 66 0f 6f ca 0f 57 c8 f3 41 0f 7f 48 10 f3 41 0f 6f 40 20 66 0f 6f ca 0f 57 c8 f3 41 0f 7f 48 20 f3 41 0f 6f 40 30 66 0f 6f ca 0f 57 c8 f3 41 0f 7f 48 30 49 83 c0 40 48 83 c2 40 48 3b d1 75 a9 } 		$a_80_1 = {61 72 69 6f 2e 6b 6f 6c 74 69 67 69 6e 2e 78 79 7a } 	condition:
		((#a_01_0  & 1)*5+(#a_80_1  & 1)*1) >=6
 
}