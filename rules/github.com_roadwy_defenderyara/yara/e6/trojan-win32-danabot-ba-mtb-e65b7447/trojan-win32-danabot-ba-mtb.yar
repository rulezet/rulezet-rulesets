rule Trojan_Win32_DanaBot_BA_MTB{
	meta:
		description = "Trojan:Win32/DanaBot.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff ff 8a 09 88 08 eb ?? 81 3d ?? ?? ?? ?? 32 09 00 00 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}