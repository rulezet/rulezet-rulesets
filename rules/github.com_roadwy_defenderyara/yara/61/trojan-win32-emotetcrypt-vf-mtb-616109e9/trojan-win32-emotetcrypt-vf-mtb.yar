rule Trojan_Win32_Emotetcrypt_VF_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 d2 8a 0c ?? 8b 45 ?? 30 ?? 3b 5d ?? 7c 90 0a 28 00 03 [0-07] f7 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}