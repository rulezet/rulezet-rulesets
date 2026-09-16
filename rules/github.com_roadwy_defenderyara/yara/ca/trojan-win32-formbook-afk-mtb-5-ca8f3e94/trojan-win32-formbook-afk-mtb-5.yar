rule Trojan_Win32_FormBook_AFK_MTB_5{
	meta:
		description = "Trojan:Win32/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 85 14 ff ff ff 7b 00 30 00 c7 85 18 ff ff ff 30 00 30 00 c7 85 1c ff ff ff 30 00 30 00 c7 85 20 ff ff ff 31 00 30 00 c7 85 24 ff ff ff 43 00 2d 00 c7 85 28 ff ff ff 30 00 30 00 c7 85 2c ff ff ff 30 00 30 00 c7 85 30 ff ff ff 2d 00 30 00 c7 85 34 ff ff ff 30 00 30 00 c7 85 38 ff ff ff 30 00 2d 00 c7 85 3c ff ff ff 43 00 30 00 c7 85 40 ff ff ff 30 00 30 00 c7 85 44 ff ff ff 2d 00 30 00 c7 85 48 ff ff ff 30 00 30 00 c7 85 4c ff ff ff 30 00 30 00 c7 85 50 ff ff ff 30 00 30 00 c7 85 54 ff ff ff 30 00 30 00 c7 85 58 ff ff ff 30 00 34 00 c7 85 5c ff ff ff 36 00 7d 00 c7 45 d0 01 00 00 00 89 7d d4 c7 45 e4 00 01 00 00 89 45 e0 ff d6 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}