rule Trojan_Win32_FormBook_AQ_MTB_2{
	meta:
		description = "Trojan:Win32/FormBook.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c1 99 6a 0c 5f f7 ff 8b 7d 10 8a 82 [0-04] 30 04 39 41 3b cb 72 } 		$a_01_1 = {83 c4 24 6a 40 68 00 30 00 00 53 56 ff 15 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}