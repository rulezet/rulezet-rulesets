rule Trojan_Win32_FormBook_AN_MTB{
	meta:
		description = "Trojan:Win32/FormBook.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 04 33 2c 33 34 1c 2c 64 34 03 2c 02 88 04 33 46 81 fe de 14 00 00 72 e7 } 	condition:
		((#a_01_0  & 1)*6) >=6
 
}