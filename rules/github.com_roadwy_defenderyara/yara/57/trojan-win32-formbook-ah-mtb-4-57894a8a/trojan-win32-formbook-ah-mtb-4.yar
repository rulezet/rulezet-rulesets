rule Trojan_Win32_FormBook_AH_MTB_4{
	meta:
		description = "Trojan:Win32/FormBook.AH!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 14 08 8b 45 e4 8b 4d d4 8a 14 08 80 c2 01 88 14 08 8b 45 e4 8b 4d d4 0f b6 34 08 89 f3 83 f3 36 88 1c 08 8b 45 e4 8b 4d d4 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}