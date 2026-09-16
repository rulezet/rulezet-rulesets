rule Ransom_Win32_StopCrypt_SK_MTB_2{
	meta:
		description = "Ransom:Win32/StopCrypt.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_00_0 = {ff 8b 85 30 ff ff ff 81 45 d4 aa a4 ab 79 81 45 70 39 2d 8e 45 81 85 24 ff ff ff a6 98 53 58 81 6d 08 9e b9 8b 52 81 ad b0 fe ff ff 03 72 47 4d } 		$a_02_1 = {f7 65 b0 8b 45 b0 81 45 0c ?? ?? ?? ?? 81 ad fc fe ff ff ?? ?? ?? ?? 81 45 bc ?? ?? ?? ?? 8b 85 80 00 00 00 30 0c 30 b8 01 00 00 00 83 f0 04 83 ad 80 00 00 00 01 39 bd 80 00 00 00 0f 8d ?? ?? ff ff } 	condition:
		((#a_00_0  & 1)*2+(#a_02_1  & 1)*2) >=4
 
}