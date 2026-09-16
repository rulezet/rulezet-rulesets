rule Trojan_Win32_AsyncRat_RPX_MTB{
	meta:
		description = "Trojan:Win32/AsyncRat.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {ba bf c0 f6 2a 30 10 40 49 0f 85 f6 ff ff ff e9 04 00 00 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}