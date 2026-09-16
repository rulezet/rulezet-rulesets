rule Trojan_Win32_FormBook_BB_MTB_2{
	meta:
		description = "Trojan:Win32/FormBook.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f 7e da 81 [0-30] 90 13 [0-30] 46 [0-30] 8b 17 [0-20] 0f 6e fe [0-25] 90 18 [0-25] 0f 6e da [0-25] 0f ef df } 		$a_02_1 = {0f 7e da 66 [0-30] 90 13 [0-30] 46 [0-30] 8b 17 [0-20] 0f 6e fe [0-25] 90 18 [0-25] 0f 6e da [0-25] 0f ef df } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}