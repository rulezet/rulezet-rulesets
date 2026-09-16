rule Trojan_Win32_Gozi_RJ_MTB{
	meta:
		description = "Trojan:Win32/Gozi.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 d0 b9 30 00 00 00 99 f7 f9 8b 45 f8 8a 14 10 8b 4d d8 8b 45 d0 32 14 01 8b 4d d0 8b 45 fc 88 14 08 ff 45 d0 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}