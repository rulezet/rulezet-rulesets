rule Trojan_Win32_Zenpack_EH_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpack.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 89 e5 56 8a 45 14 8b 4d 10 8b 55 0c 8b 75 08 c7 05 ?? ?? ?? ?? 97 00 00 00 8a 24 0a 28 c4 c7 05 ?? ?? ?? ?? 5d 08 00 00 88 24 0e 5e 5d c3 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}