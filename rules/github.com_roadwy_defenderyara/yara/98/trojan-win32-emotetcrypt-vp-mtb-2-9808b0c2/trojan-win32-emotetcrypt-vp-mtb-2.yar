rule Trojan_Win32_Emotetcrypt_VP_MTB_2{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 54 24 [0-02] 8b 0d [0-04] 8b 44 [0-02] 8a 14 [0-02] 30 14 [0-02] 8b 44 [0-02] 43 3b d8 0f 8c [0-04] 8a [0-04] 8b [0-04] 8a [0-04] 5f [0-02] 88 [0-02] 88 [0-02] 5b 59 c3 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}