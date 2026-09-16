rule Trojan_Win32_Gozi_RE_MTB_2{
	meta:
		description = "Trojan:Win32/Gozi.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 f9 8b 8d 80 ee ff ff 40 0f af 85 6c ee ff ff 03 c6 03 05 ?? ?? ?? ?? 99 f7 bd 74 ee ff ff 8b 85 78 ee ff ff 30 14 01 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}