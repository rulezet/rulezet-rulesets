rule Ransom_Win32_StopCrypt_PBP_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PBP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c0 50 50 50 ff 15 ?? ?? ?? ?? 8b 45 ?? 83 25 ?? ?? ?? ?? 00 81 45 ?? 47 86 c8 61 33 c3 2b f8 ff [0-06] 89 [0-06] 0f 85 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}