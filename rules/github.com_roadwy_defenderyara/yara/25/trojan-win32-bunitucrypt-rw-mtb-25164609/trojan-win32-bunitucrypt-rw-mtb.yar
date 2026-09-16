rule Trojan_Win32_Bunitucrypt_RW_MTB{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d8 8b 45 ?? 03 45 ?? 2d 67 2b 00 00 03 45 ?? 03 d8 e8 ?? ?? ?? ?? 2b d8 8b 45 ?? 31 18 6a 00 e8 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}