rule Trojan_Win32_Lazy_KK_MTB{
	meta:
		description = "Trojan:Win32/Lazy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 08 32 ca 02 ca 88 08 40 4e } 		$a_01_1 = {44 6b 63 73 6b 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}