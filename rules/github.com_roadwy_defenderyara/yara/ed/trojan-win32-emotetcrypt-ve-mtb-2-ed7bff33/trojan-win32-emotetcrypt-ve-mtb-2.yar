rule Trojan_Win32_Emotetcrypt_VE_MTB_2{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c2 33 d2 f7 f1 [0-04] 03 55 [0-02] 8a 04 32 [0-04] 02 45 [0-02] 32 04 [0-02] 88 07 47 ff 4d [0-02] 75 [0-02] 5f 5e 5b c9 c3 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}