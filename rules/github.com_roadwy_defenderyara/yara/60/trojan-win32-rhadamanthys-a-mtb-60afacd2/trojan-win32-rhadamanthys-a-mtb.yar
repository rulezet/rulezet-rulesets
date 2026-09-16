rule Trojan_Win32_Rhadamanthys_A_MTB{
	meta:
		description = "Trojan:Win32/Rhadamanthys.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {ff 95 e8 e5 ff ff } 		$a_02_1 = {f7 fb 89 74 24 20 db 44 24 20 d9 05 f8 ff 81 11 d9 c1 d8 c9 89 44 24 10 db 44 24 10 8b 84 24 ?? 00 00 00 de f9 d9 5c 24 6c d9 44 24 6c d9 80 f8 95 00 00 d9 c0 d8 35 fc ff 81 11 d9 05 e4 ff 81 11 d9 5c 24 5c d9 cb df f3 } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}