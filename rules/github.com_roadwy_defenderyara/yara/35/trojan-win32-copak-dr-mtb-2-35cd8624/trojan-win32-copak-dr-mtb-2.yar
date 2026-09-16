rule Trojan_Win32_Copak_DR_MTB_2{
	meta:
		description = "Trojan:Win32/Copak.DR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 d6 81 e2 ff 00 00 00 f7 d0 b8 24 77 f9 44 31 11 81 c0 f1 d6 28 f7 81 c3 67 c7 45 6c 21 de 81 c1 01 00 00 00 89 f3 be 0b a1 0b a8 47 81 eb dd 9c 8a 58 21 c3 09 db 81 f9 b8 af 47 00 0f } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}