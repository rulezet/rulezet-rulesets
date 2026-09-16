rule Trojan_Win32_FormBook_AFK_MTB_3{
	meta:
		description = "Trojan:Win32/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 44 24 06 5f c6 44 24 0c 79 c6 44 24 03 65 c6 44 24 04 6c c6 44 24 08 6f c6 44 24 0e 63 c6 04 24 48 c6 44 24 0a 69 c6 44 24 01 53 c6 44 24 0f 6f c6 44 24 07 4e c6 44 24 0d 49 c6 44 24 02 68 c6 44 24 0b 66 c6 44 24 11 41 c6 44 24 05 6c c6 44 24 09 74 c6 44 24 10 6e } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}