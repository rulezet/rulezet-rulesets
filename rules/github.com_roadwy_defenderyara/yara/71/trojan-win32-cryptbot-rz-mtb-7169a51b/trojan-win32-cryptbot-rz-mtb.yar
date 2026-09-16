rule Trojan_Win32_CryptBot_RZ_MTB{
	meta:
		description = "Trojan:Win32/CryptBot.RZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 20 20 00 20 20 20 20 00 b0 6d 00 00 10 00 00 00 8a 28 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 ac 01 00 00 00 c0 6d 00 00 02 00 00 00 9a 28 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}