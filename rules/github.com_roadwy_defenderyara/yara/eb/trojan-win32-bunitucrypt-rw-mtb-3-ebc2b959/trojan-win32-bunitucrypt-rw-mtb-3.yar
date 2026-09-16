rule Trojan_Win32_Bunitucrypt_RW_MTB_3{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 18 8b 45 ?? 03 ?? ?? 03 ?? ?? 8b ?? ?? 31 02 83 ?? ?? 04 83 ?? ?? 04 8b ?? ?? 3b ?? ?? 0f 82 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}