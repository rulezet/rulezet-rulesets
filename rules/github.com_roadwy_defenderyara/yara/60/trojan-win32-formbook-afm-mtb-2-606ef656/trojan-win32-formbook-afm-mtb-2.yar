rule Trojan_Win32_FormBook_AFM_MTB_2{
	meta:
		description = "Trojan:Win32/FormBook.AFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 f6 89 f6 89 f6 89 f6 89 f6 8b 4d fc 03 cf 89 f6 89 f6 8a 10 89 f6 89 f6 89 f6 89 f6 32 55 fa 88 11 89 f6 8a 55 fb 30 11 89 f6 89 f6 89 f6 89 f6 47 40 4e } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}