rule Trojan_Win32_Bunitucrypt_RW_MTB_15{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c0 89 45 ?? 8b 45 ?? 3b 45 ?? 0f 83 ?? ?? ?? ?? 8b 45 ?? 8b 55 ?? 01 02 8b 45 ?? 05 8a a5 08 00 03 45 ?? 8b 55 ?? 31 02 68 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}