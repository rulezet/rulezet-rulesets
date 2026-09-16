rule Trojan_Win32_LummaStealer_NDS_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.NDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {59 eb 02 33 f6 33 db 56 e8 d6 db ff ff 59 8b c3 8d 65 ec 5f 5e 5b 8b 4d fc 33 cd e8 } 		$a_01_1 = {75 ef 56 e8 a4 03 00 00 eb 06 56 e8 83 00 00 00 33 c0 59 8b 4d fc 5f 5e 33 cd 5b e8 f4 96 ff ff c9 c3 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}