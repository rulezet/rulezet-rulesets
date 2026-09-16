rule Trojan_Win32_C2Lop_B{
	meta:
		description = "Trojan:Win32/C2Lop.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {51 55 57 8b 1f 8b 4f 04 ba b9 79 (37|39) 9e 8b c2 c1 e0 04 bf 10 00 00 00 8b eb c1 e5 04 2b cd 8b 6e 08 33 eb 2b cd 8b eb c1 ed 05 33 e8 2b cd 2b 4e 0c 8b e9 c1 e5 04 2b dd 8b 2e 33 e9 2b dd 8b e9 c1 ed 05 33 e8 2b dd 2b 5e 04 2b c2 4f } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}