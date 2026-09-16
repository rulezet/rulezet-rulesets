rule Trojan_Win32_Bunitucrypt_RMA_MTB_2{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 2d 16 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 68 2d 16 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 ?? 31 18 6a 00 e8 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}