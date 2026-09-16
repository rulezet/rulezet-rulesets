rule Trojan_Win32_Fareit_BA_MTB{
	meta:
		description = "Trojan:Win32/Fareit.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 08 32 1d ?? ?? ?? ?? 88 18 ff 07 81 3f 58 6c 00 00 75 } 	condition:
		((#a_03_0  & 1)*3) >=3
 
}