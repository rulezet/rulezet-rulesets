rule Trojan_Win32_Emotetcrypt_VB_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {41 03 c2 0f b6 54 24 ?? 8a 14 32 30 10 3b 4c 24 ?? 89 4c 24 ?? 0f 8c } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}