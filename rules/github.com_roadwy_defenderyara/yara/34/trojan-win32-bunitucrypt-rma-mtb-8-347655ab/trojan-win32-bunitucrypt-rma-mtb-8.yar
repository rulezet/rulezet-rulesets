rule Trojan_Win32_Bunitucrypt_RMA_MTB_8{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d8 8b 45 ?? 31 18 6a 00 e8 ?? ?? ?? ?? 8b d8 8b 45 ?? 83 c0 04 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 89 [0-05] 8b [0-05] 83 c0 04 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}