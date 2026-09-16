rule Trojan_Win32_FormBook_AFB_MTB_3{
	meta:
		description = "Trojan:Win32/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 47 54 46 8a 40 03 30 44 1e ff 0f b6 4c 1e ff 8b 47 54 8a 50 02 32 d1 88 54 1e ff 8b 47 54 8a 48 01 32 ca 88 4c 1e ff 8b 47 54 8a 00 32 c1 88 44 1e ff } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}