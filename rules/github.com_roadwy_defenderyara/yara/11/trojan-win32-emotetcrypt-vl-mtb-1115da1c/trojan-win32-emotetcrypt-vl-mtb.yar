rule Trojan_Win32_Emotetcrypt_VL_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c2 99 b9 [0-04] f7 f9 [0-19] 0f b6 [0-04] a1 [0-04] 8a 0c [0-02] 8b 44 [0-02] 30 0c 28 8b 44 [0-02] 45 3b e8 0f 8c } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}