rule Trojan_Win32_FormBook_CR_MTB{
	meta:
		description = "Trojan:Win32/FormBook.CR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {88 02 ff 45 ?? 81 7d [0-30] 90 13 [0-30] 8b 45 ?? 83 e0 [0-30] 8b 45 ?? 8a 80 [0-20] 34 ?? 8b 55 ?? 03 55 ?? 88 02 [0-30] 8b 45 ?? 8a 80 [0-20] 8b 55 ?? 03 55 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}