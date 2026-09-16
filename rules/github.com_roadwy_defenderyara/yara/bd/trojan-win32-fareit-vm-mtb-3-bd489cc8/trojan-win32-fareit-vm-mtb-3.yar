rule Trojan_Win32_Fareit_VM_MTB_3{
	meta:
		description = "Trojan:Win32/Fareit.VM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {e8 c3 29 f9 ff 8a 84 85 e8 fb ff ff 30 06 } 		$a_03_1 = {8a 84 9d e8 fb ff ff 88 45 ?? 89 c0 89 f6 89 d2 87 ff 8b 84 bd e8 fb ff ff 89 84 9d e8 fb ff ff 90 90 89 db 90 90 33 c0 8a 45 ?? 89 84 bd } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}