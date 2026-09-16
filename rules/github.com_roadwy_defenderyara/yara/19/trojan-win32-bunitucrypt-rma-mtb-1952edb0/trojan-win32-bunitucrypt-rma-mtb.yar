rule Trojan_Win32_Bunitucrypt_RMA_MTB{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2d f2 05 00 00 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 31 02 6a 00 e8 ?? ?? ?? ?? 8b d8 83 c3 04 6a } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}