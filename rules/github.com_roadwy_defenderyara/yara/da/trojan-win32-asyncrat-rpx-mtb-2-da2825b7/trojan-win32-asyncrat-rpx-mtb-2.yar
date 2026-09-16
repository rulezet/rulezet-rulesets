rule Trojan_Win32_AsyncRat_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/AsyncRat.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 10 00 00 ff 74 24 10 6a 00 ff 15 ?? ?? ?? ?? 8b f0 85 f6 74 21 ff 74 24 08 ff 74 24 10 56 e8 1f 12 00 00 83 c4 0c ff d6 68 00 80 00 00 6a 00 56 ff 15 ?? ?? ?? ?? ff 74 24 0c e8 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}