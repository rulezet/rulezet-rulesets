rule Trojan_Win32_Bunitucrypt_RMA_MTB_13{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d8 8b 45 ?? 31 18 6a ?? e8 ?? ?? ?? ?? 8b d8 83 c3 04 6a ?? e8 ?? ?? ?? ?? 2b d8 01 5d ?? 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}