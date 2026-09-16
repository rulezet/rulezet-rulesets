rule Trojan_Win32_Emotetcrypt_VG_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {ff d6 53 53 ff d6 8b 45 [0-02] 8a 0c [0-02] 02 4d [0-02] 8b 45 [0-02] 8b 55 [0-02] 32 0c [0-02] 88 08 40 ff 4d [0-02] 89 45 [0-02] 0f 85 [0-04] 5f 5e 5b c9 c3 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}