rule Ransom_Win32_StopCrypt_PAG_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 45 08 8b 45 f0 83 25 ?? ?? ?? ?? ?? 03 c8 33 4d 08 33 4d 0c 89 4d 08 8b 45 08 01 05 ?? ?? ?? ?? 2b 7d 08 89 7d fc 8b 45 fc 03 45 f8 89 45 0c } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}