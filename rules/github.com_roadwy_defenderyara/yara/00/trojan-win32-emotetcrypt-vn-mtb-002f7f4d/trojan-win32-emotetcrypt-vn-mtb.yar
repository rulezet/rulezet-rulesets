rule Trojan_Win32_Emotetcrypt_VN_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 54 24 [0-01] a1 [0-04] 8a 0c [0-01] 8b 44 [0-02] 30 0c [0-01] 8b 44 [0-02] [0-01] 3b [0-01] 0f 8c [0-04] 8b [0-03] 8a [0-03] 8a [0-03] 5f 5d 5e 88 [0-01] 88 [0-02] 5b 59 c3 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}