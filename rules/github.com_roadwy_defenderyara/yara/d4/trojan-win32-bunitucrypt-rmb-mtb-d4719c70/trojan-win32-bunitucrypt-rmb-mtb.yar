rule Trojan_Win32_Bunitucrypt_RMB_MTB{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 8b ?? ?? 3b ?? ?? 0f [0-09] 8b ?? ?? 8b ?? ?? 01 02 8b ?? ?? 03 ?? ?? 03 ?? ?? 8b ?? ?? 31 02 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}