rule Trojan_Win32_Emotet_BA_MTB{
	meta:
		description = "Trojan:Win32/Emotet.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c2 25 ff 00 00 80 79 ?? 48 0d 00 ff ff ff 40 89 45 ?? 8b 45 ?? 0f b6 88 ?? ?? ?? ?? 8b 55 ?? 0f b6 84 15 ?? ?? ?? ?? 33 c8 8b 55 ?? 88 8a ?? ?? ?? ?? e9 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}