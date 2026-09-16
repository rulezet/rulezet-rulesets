rule Trojan_Win32_Zenpack_EH_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {fd ff ff 0f b6 c8 83 e9 33 8b 95 ?? fd ff ff 89 8d ?? fd ff ff 89 95 d8 fd ff ff 74 } 	condition:
		((#a_03_0  & 1)*3) >=3
 
}