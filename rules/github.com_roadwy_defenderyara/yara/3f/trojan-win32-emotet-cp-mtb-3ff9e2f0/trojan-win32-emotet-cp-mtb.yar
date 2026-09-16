rule Trojan_Win32_Emotet_CP_MTB{
	meta:
		description = "Trojan:Win32/Emotet.CP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8d a4 24 00 00 00 00 47 81 e7 ff 00 00 00 0f b6 54 3c ?? 03 ea 81 e5 ff 00 00 00 0f b6 44 2c ?? 88 44 3c ?? 02 c2 88 54 2c ?? 0f b6 d0 8a 54 14 ?? 8b 44 24 0c 30 14 08 41 3b ce 7c } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}