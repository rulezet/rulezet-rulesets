rule Trojan_Win32_Tinba_MA_MTB{
	meta:
		description = "Trojan:Win32/Tinba.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {8d 85 60 ff ff ff 8d 4d a0 b2 00 8a b5 57 ff ff ff 80 f6 02 88 b5 57 ff ff ff 2a 95 4f ff ff ff 89 0c 24 89 44 24 04 8b 85 08 ff ff ff 89 44 24 08 88 95 f7 fe ff ff e8 3c bd ff ff 8b 4d 88 8a 95 57 ff ff ff 80 ca 6e 8a b5 f7 fe ff ff 88 b5 4f ff ff ff 88 95 57 ff ff ff 8b b5 1c ff ff ff 39 f1 89 85 f0 fe ff ff 0f 85 } 		$a_01_1 = {43 72 65 61 74 65 4d 61 69 6c 73 6c 6f 74 57 47 65 74 54 69 63 6b 43 6f 75 6d } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}