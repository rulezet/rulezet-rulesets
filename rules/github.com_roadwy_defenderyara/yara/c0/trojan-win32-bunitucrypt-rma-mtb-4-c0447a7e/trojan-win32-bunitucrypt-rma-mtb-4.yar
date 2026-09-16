rule Trojan_Win32_Bunitucrypt_RMA_MTB_4{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d8 8b 45 ?? 03 45 ?? 2d 29 09 00 00 03 45 ?? 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 8b 45 ?? 31 18 6a } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}