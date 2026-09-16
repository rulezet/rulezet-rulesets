rule Ransom_Win32_StopCrypt_MWK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MWK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d1 31 55 ?? 8b 55 90 1b 00 8d 8d ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 3d ?? ?? ?? ?? ?? 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}