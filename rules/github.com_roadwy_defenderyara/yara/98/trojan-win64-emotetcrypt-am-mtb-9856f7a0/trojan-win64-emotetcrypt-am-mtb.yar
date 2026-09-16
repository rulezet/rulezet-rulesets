rule Trojan_Win64_Emotetcrypt_AM_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff c3 49 f7 e3 49 8b c3 48 2b c2 48 d1 e8 48 03 c2 48 c1 e8 05 48 6b c0 3e 4c 2b d8 4c 03 dd 43 8a 04 23 4c 63 db 41 32 00 49 ff c0 88 01 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}