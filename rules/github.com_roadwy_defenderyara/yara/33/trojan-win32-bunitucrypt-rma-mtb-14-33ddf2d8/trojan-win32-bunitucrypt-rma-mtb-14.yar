rule Trojan_Win32_Bunitucrypt_RMA_MTB_14{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 d8 8b 45 ?? 31 18 83 45 e8 04 83 45 ec 04 8b 45 e8 3b 45 e0 0f 82 ?? ?? ?? ?? c7 45 ?? 00 10 00 00 8b 45 ?? 03 45 ?? 2b 45 ?? 83 c0 04 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}