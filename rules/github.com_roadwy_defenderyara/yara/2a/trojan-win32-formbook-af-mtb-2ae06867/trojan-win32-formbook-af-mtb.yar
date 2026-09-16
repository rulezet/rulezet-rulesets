rule Trojan_Win32_FormBook_AF_MTB{
	meta:
		description = "Trojan:Win32/FormBook.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 55 10 6a 00 8d 4d fc 51 53 8b f0 56 52 ff 15 ?? ?? ?? ?? 80 04 3e f1 47 3b fb } 		$a_01_1 = {43 72 65 61 74 65 46 69 6c 65 57 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}