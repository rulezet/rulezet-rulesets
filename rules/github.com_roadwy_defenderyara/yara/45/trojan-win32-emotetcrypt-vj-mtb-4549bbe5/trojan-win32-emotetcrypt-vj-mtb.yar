rule Trojan_Win32_Emotetcrypt_VJ_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c7 2b 05 [0-04] 47 03 c8 0f b6 c3 8b 1d [0-04] 8a 04 [0-01] 30 01 8b 4d [0-01] 3b fe } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}