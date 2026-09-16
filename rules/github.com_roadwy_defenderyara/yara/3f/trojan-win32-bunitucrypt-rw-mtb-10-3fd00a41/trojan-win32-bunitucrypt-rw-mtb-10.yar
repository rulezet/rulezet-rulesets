rule Trojan_Win32_Bunitucrypt_RW_MTB_10{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d8 8b 45 ?? 89 18 8b 45 ?? 03 45 ?? 03 45 ?? 03 45 ?? 8b 55 ?? 31 02 83 45 ?? 04 83 45 ?? 04 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}